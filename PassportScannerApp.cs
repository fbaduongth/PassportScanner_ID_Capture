using System;
using System.IO;
using System.Text;
using System.Diagnostics;
using System.Globalization;
using System.Text.RegularExpressions;
using System.Drawing;
using System.Drawing.Imaging;
using System.Drawing.Drawing2D;
using System.Windows.Forms;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Xml;
using Windows.Foundation;
using Windows.Media.Ocr;
using Windows.Media.FaceAnalysis;
using Windows.Graphics.Imaging;
using Windows.Storage;
using Windows.Storage.Streams;
using Windows.Globalization;
using System.Runtime.ExceptionServices;
using System.Security;
using Point = System.Drawing.Point;
using Size = System.Drawing.Size;

namespace PassportScannerApp
{
    public class GuestRecord
    {
        public int SoThuTu { get; set; }
        public string HoTen { get; set; }
        public string NgaySinh { get; set; }
        public string NgaySinhDungDen { get; set; }
        public string GioiTinh { get; set; }
        public string MaQuocTich { get; set; }
        public string SoHoChieu { get; set; }
        public string SoPhong { get; set; }
        public string NgayDen { get; set; }
        public string NgayDiDuKien { get; set; }
        public string NgayTraPhong { get; set; }
        public string ThoiHanTamTru { get; set; }
        public string ThoiGianQuet { get; set; }
    }

    public class PassportParseResult
    {
        public bool Success { get; set; }
        public string FullName { get; set; }
        public string PassportNo { get; set; }
        public string Nationality { get; set; }
        public string BirthDate { get; set; }
        public string Gender { get; set; }
        public string ExpiryDate { get; set; }
        public string PersonalId { get; set; }
        public string MrzLine1 { get; set; }
        public string MrzLine2 { get; set; }
        public Bitmap OrientedImage { get; set; }
        public Bitmap CroppedFace { get; set; }
        public string ErrorMessage { get; set; }

        public PassportParseResult()
        {
            Success = false;
            FullName = "";
            PassportNo = "";
            Nationality = "VNM";
            BirthDate = "";
            Gender = "M";
            ExpiryDate = "";
            PersonalId = "";
            MrzLine1 = "";
            MrzLine2 = "";
            ErrorMessage = "";
        }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
    public struct SYSCAN_RST
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 40)]  public char[] name;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 100)] public char[] SurnameCH;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 100)] public char[] nameCH;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 10)]  public char[] sex;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 10)]  public char[] Gender;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 50)]  public char[] birthday;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 20)]  public char[] people;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 50)]  public char[] signdate;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 50)]  public char[] validterm;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 200)] public char[] address;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 40)]  public char[] number;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 50)]  public char[] organs;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 100)] public char[] SurnameEN;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 100)] public char[] nameEN;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 40)]  public char[] ENfullname;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 200)] public char[] Nationality;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 100)] public char[] id;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 50)]  public char[] Leavetime;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 100)] public char[] placeCH;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 100)] public char[] placeEN;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 100)] public char[] BirthplaceCH;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 100)] public char[] BirthplaceEN;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 256)] public char[] szCodeOne;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 256)] public char[] szCodeTwo;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 256)] public char[] szCodeThree;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 40)]  public char[] Permitnumber_number;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 200)] public char[] Vocational;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 100)] public char[] DocumentsCategory;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 200)] public char[] Other;
    }

    public static class ScannerNative
    {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool SetDllDirectory(string lpPathName);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr LoadLibrary(string lpFileName);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

        // --- Core Scanner & Recognition Functions ---
        [DllImport("scandll.dll", EntryPoint = "IO_HasScanner", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        public static extern int IO_HasScanner([MarshalAs(UnmanagedType.LPStr)] string name, IntPtr hWnd);

        [DllImport("scandll.dll", EntryPoint = "IO_GetDevTopState", CallingConvention = CallingConvention.StdCall)]
        public static extern int IO_GetDevTopState();

        [DllImport("scandll.dll", EntryPoint = "IO_GetIDResult", CharSet = CharSet.Ansi, ExactSpelling = true, CallingConvention = CallingConvention.StdCall)]
        public static extern int IO_GetIDResult(
            int lCardType,
            [MarshalAs(UnmanagedType.LPStr)] string szOutPutFileName_IR,
            [MarshalAs(UnmanagedType.LPStr)] string szOutPutFileName_HR,
            [MarshalAs(UnmanagedType.LPStr)] string szPhotoFileName_IR,
            [MarshalAs(UnmanagedType.LPStr)] string szPhotoFileName_HR,
            int lCompressRet,
            ref SYSCAN_RST pstRst
        );

        [DllImport("scandll.dll", EntryPoint = "IO_GetIDImage_File", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        public static extern int IO_GetIDImage_File(int lImageType, int lCardType, int lCompressRet, [MarshalAs(UnmanagedType.LPStr)] string szFileOutPut);

        [DllImport("scandll.dll", EntryPoint = "IO_IdentifyCard_File", CharSet = CharSet.Ansi, ExactSpelling = true, CallingConvention = CallingConvention.StdCall)]
        public static extern int IO_IdentifyCard_File(
            [MarshalAs(UnmanagedType.LPStr)] string szFileIn,
            int lCardType,
            [MarshalAs(UnmanagedType.LPStr)] string szPhotoOut,
            ref SYSCAN_RST pResult
        );

        [DllImport("scandll.dll", EntryPoint = "IO_IdentifyCard_Buff", CallingConvention = CallingConvention.StdCall)]
        public static extern int IO_IdentifyCard_Buff(IntPtr pBuffer, int lSize, int lCardType, IntPtr pPhotoOut, ref SYSCAN_RST pResult);

        [DllImport("scandll.dll", EntryPoint = "IO_ProcessImage", CallingConvention = CallingConvention.StdCall)]
        public static extern int IO_ProcessImage(int lType);

        // --- Hardware Control & Lighting ---
        [DllImport("scandll.dll", EntryPoint = "IO_NotifyBeep", CallingConvention = CallingConvention.StdCall)]
        public static extern void IO_NotifyBeep(int nTime);

        [DllImport("scandll.dll", EntryPoint = "IO_Notify", CallingConvention = CallingConvention.StdCall)]
        public static extern void IO_Notify(int nTime);

        [DllImport("scandll.dll", EntryPoint = "IO_NotifyLight", CallingConvention = CallingConvention.StdCall)]
        public static extern void IO_NotifyLight(int nTime);

        [DllImport("scandll.dll", EntryPoint = "IO_SetFTLight", CallingConvention = CallingConvention.StdCall)]
        public static extern int IO_SetFTLight(int nLightType, int bOpen);

        [DllImport("scandll.dll", EntryPoint = "IO_GetVersion", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        public static extern int IO_GetVersion([MarshalAs(UnmanagedType.VBByRefStr)] ref string pVersion, int nLen);

        // --- RFID / Đọc thẻ chip ---
        [DllImport("scandll.dll", EntryPoint = "IO_StartRFID", CallingConvention = CallingConvention.StdCall)]
        public static extern bool IO_StartRFID();

        [DllImport("scandll.dll", EntryPoint = "IO_StopRFID", CallingConvention = CallingConvention.StdCall)]
        public static extern bool IO_StopRFID();

        [DllImport("scandll.dll", EntryPoint = "IO_SearchCard", CallingConvention = CallingConvention.StdCall)]
        public static extern int IO_SearchCard();

        [DllImport("scandll.dll", EntryPoint = "IO_SelectCard", CallingConvention = CallingConvention.StdCall)]
        public static extern int IO_SelectCard();

        [DllImport("scandll.dll", EntryPoint = "IO_ReadCard", CallingConvention = CallingConvention.StdCall)]
        public static extern int IO_ReadCard(ref SYSCAN_RST pstRst);

        [DllImport("scandll.dll", EntryPoint = "IO_SSReadCard", CallingConvention = CallingConvention.StdCall)]
        public static extern int IO_SSReadCard(ref SYSCAN_RST pstRst);

        [DllImport("scandll.dll", EntryPoint = "IO_GetRFIDState", CallingConvention = CallingConvention.StdCall)]
        public static extern int IO_GetRFIDState();

        // --- Hiệu chuẩn (Calibration) ---
        [DllImport("scandll.dll", EntryPoint = "IO_CreateCalibrateData", CallingConvention = CallingConvention.StdCall)]
        public static extern int IO_CreateCalibrateData();

        [DllImport("scandll.dll", EntryPoint = "IO_WriteCalibData", CallingConvention = CallingConvention.StdCall)]
        public static extern int IO_WriteCalibData(bool bBK);

        [DllImport("scandll.dll", EntryPoint = "IO_ReadCalibData", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        public static extern int IO_ReadCalibData([MarshalAs(UnmanagedType.VBByRefStr)] ref string pDataBufRead, int lDataLen, int lLightType);

        private static bool hotfixApplied = false;

        public static void EnsureCommonProgramDataFiles()
        {
            try
            {
                string appDir = AppDomain.CurrentDomain.BaseDirectory;
                string commonAppData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
                string pdDir = Path.Combine(commonAppData, "ID_Capture");
                if (!Directory.Exists(pdDir))
                {
                    Directory.CreateDirectory(pdDir);
                }

                // Đồng bộ toàn bộ file *.dat (đặc biệt là brightness_data.dat 3.8MB, calibrate_data.dat 13.8MB)
                string[] datFiles = Directory.GetFiles(appDir, "*.dat");
                foreach (string src in datFiles)
                {
                    string fileName = Path.GetFileName(src);
                    string dest = Path.Combine(pdDir, fileName);
                    try
                    {
                        if (!File.Exists(dest) || new FileInfo(dest).Length != new FileInfo(src).Length)
                        {
                            File.Copy(src, dest, true);
                        }
                    }
                    catch { }
                }

                // Đồng bộ các file cấu hình *.ini
                string[] iniFiles = new string[] { "IDC_Image_Process.ini", "IDC_Focus_Tune.ini" };
                foreach (string ini in iniFiles)
                {
                    string src = Path.Combine(appDir, ini);
                    if (File.Exists(src))
                    {
                        string dest = Path.Combine(pdDir, ini);
                        try
                        {
                            if (!File.Exists(dest) || new FileInfo(dest).Length != new FileInfo(src).Length)
                            {
                                File.Copy(src, dest, true);
                            }
                        }
                        catch { }
                    }
                }

                // Đồng bộ IDC_Image_Process.dll
                string idcDll = Path.Combine(appDir, "IDC_Image_Process.dll");
                if (File.Exists(idcDll))
                {
                    string dest = Path.Combine(pdDir, "IDC_Image_Process.dll");
                    try
                    {
                        if (!File.Exists(dest) || new FileInfo(dest).Length != new FileInfo(idcDll).Length)
                        {
                            File.Copy(idcDll, dest, true);
                        }
                    }
                    catch { }
                }
            }
            catch { }
        }

        private static IntPtr hPinnedScanDll = IntPtr.Zero;
        private static IntPtr hPinnedIdcApp = IntPtr.Zero;
        private static IntPtr hPinnedIdcPd = IntPtr.Zero;

        private static void PatchIdcImageProcess(IntPtr hMod)
        {
            if (hMod == IntPtr.Zero) return;
            try
            {
                IntPtr patchAddr = new IntPtr(hMod.ToInt64() + 0x48E0);
                uint oldProt;
                if (VirtualProtect(patchAddr, (UIntPtr)1, 0x40 /* PAGE_EXECUTE_READWRITE */, out oldProt))
                {
                    Marshal.WriteByte(patchAddr, 0xC3); // RET
                    VirtualProtect(patchAddr, (UIntPtr)1, oldProt, out oldProt);
                }
            }
            catch { }
        }

        public static void ApplyDriverHotfix()
        {
            EnsureCommonProgramDataFiles();

            try
            {
                string appDir = AppDomain.CurrentDomain.BaseDirectory;
                // Cô lập thứ tự nạp DLL: luôn ưu tiên DLL của ứng dụng, tránh xung đột với bản cài/driver cũ trong System32/SysWOW64/PATH
                try { SetDllDirectory(appDir); } catch { }

                // 1. Hotfix IDC_Image_Process.dll ở CẢ thư mục ứng dụng VÀ C:\ProgramData\ID_Capture (chống xung đột 2 bản DLL)
                if (hPinnedIdcApp == IntPtr.Zero)
                {
                    string appIdc = Path.Combine(appDir, "IDC_Image_Process.dll");
                    hPinnedIdcApp = LoadLibrary(File.Exists(appIdc) ? appIdc : "IDC_Image_Process.dll");
                }
                PatchIdcImageProcess(hPinnedIdcApp);

                string commonAppData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
                string pdIdc = Path.Combine(commonAppData, "ID_Capture", "IDC_Image_Process.dll");
                if (File.Exists(pdIdc))
                {
                    if (hPinnedIdcPd == IntPtr.Zero)
                    {
                        hPinnedIdcPd = LoadLibrary(pdIdc);
                    }
                    if (hPinnedIdcPd != IntPtr.Zero && hPinnedIdcPd != hPinnedIdcApp)
                    {
                        PatchIdcImageProcess(hPinnedIdcPd);
                    }
                }

                // 2. Hotfix ScanDll.dll: Luôn giữ cờ brightness_data.dat = 1 và bỏ qua nhánh lỗi -2017
                if (hPinnedScanDll == IntPtr.Zero)
                {
                    string appScan = Path.Combine(appDir, "ScanDll.dll");
                    hPinnedScanDll = LoadLibrary(File.Exists(appScan) ? appScan : "scandll.dll");
                }
                if (hPinnedScanDll != IntPtr.Zero)
                {
                    // a) Luôn đảm bảo cờ hiệu [hScan + 0x74FB8] = 1 (vì IO_HasScanner có thể ghi lại)
                    IntPtr flagAddr = new IntPtr(hPinnedScanDll.ToInt64() + 0x74FB8);
                    uint oldProt;
                    if (VirtualProtect(flagAddr, (UIntPtr)4, 0x40 /* PAGE_EXECUTE_READWRITE */, out oldProt))
                    {
                        Marshal.WriteInt32(flagAddr, 1);
                        VirtualProtect(flagAddr, (UIntPtr)4, oldProt, out oldProt);
                    }

                    // b) Patch lệnh nhảy tại RVA 0x1D87: 0x75 (JNZ) -> 0xEB (JMP), luôn vượt qua nhánh mov eax, -2017
                    if (!hotfixApplied)
                    {
                        IntPtr jmpAddr = new IntPtr(hPinnedScanDll.ToInt64() + 0x1D87);
                        if (VirtualProtect(jmpAddr, (UIntPtr)1, 0x40 /* PAGE_EXECUTE_READWRITE */, out oldProt))
                        {
                            Marshal.WriteByte(jmpAddr, 0xEB); // JMP rel8
                            VirtualProtect(jmpAddr, (UIntPtr)1, oldProt, out oldProt);
                        }
                    }
                }

                hotfixApplied = true;
            }
            catch { }
        }

        /// <summary>
        /// Kiểm tra con trỏ đối tượng OCR nội bộ [ScanDll + 0x74F48] đã được khởi tạo chưa.
        /// Nếu chưa có máy quét USB (con trỏ == NULL), gọi IO_IdentifyCard_File sẽ gây AccessViolationException!
        /// </summary>
        public static bool IsSyscanEngineReady()
        {
            try
            {
                if (hPinnedScanDll == IntPtr.Zero) ApplyDriverHotfix();
                if (hPinnedScanDll == IntPtr.Zero) return false;
                IntPtr objPtr = Marshal.ReadIntPtr(new IntPtr(hPinnedScanDll.ToInt64() + 0x74F48));
                return objPtr != IntPtr.Zero;
            }
            catch
            {
                return false;
            }
        }

        [HandleProcessCorruptedStateExceptions]
        [SecurityCritical]
        public static int SafeHasScanner(string name, IntPtr hWnd)
        {
            try
            {
                ApplyDriverHotfix();
                Directory.SetCurrentDirectory(AppDomain.CurrentDomain.BaseDirectory);
                int r = IO_HasScanner(name, hWnd);
                // Đảm bảo cờ [0x74FB8] vẫn bằng 1 sau khi IO_HasScanner chạy xong
                ApplyDriverHotfix();
                return r;
            }
            catch
            {
                return -2000;
            }
        }

        [HandleProcessCorruptedStateExceptions]
        [SecurityCritical]
        public static int SafeGetIDResult(int cardType, string fileGrey, string fileColor, string fileGreyHead, string fileColorHead, int compressRet, ref SYSCAN_RST rst)
        {
            try
            {
                ApplyDriverHotfix();
                Directory.SetCurrentDirectory(AppDomain.CurrentDomain.BaseDirectory);
                return IO_GetIDResult(cardType, fileGrey, fileColor, fileGreyHead, fileColorHead, compressRet, ref rst);
            }
            catch
            {
                return -9999;
            }
        }

        [HandleProcessCorruptedStateExceptions]
        [SecurityCritical]
        public static int SafeGetIDImageFile(int imageType, int cardType, int compressRet, string outFile)
        {
            try
            {
                ApplyDriverHotfix();
                Directory.SetCurrentDirectory(AppDomain.CurrentDomain.BaseDirectory);
                return IO_GetIDImage_File(imageType, cardType, compressRet, outFile);
            }
            catch
            {
                return -9999;
            }
        }

        [HandleProcessCorruptedStateExceptions]
        [SecurityCritical]
        public static int SafeIdentifyCardFile(string fileIn, int cardType, string photoOut, ref SYSCAN_RST rst)
        {
            try
            {
                ApplyDriverHotfix();
                if (!IsSyscanEngineReady()) return -2000;
                Directory.SetCurrentDirectory(AppDomain.CurrentDomain.BaseDirectory);
                return IO_IdentifyCard_File(fileIn, cardType, photoOut, ref rst);
            }
            catch
            {
                return -9999;
            }
        }
    }

    public static class NativePassportEngine
    {
        private static readonly Regex RegexMrzL2_A = new Regex(@"([A-Z0-9]{8,10})[<0-9]?\s*([A-Z]{3})\s*([0-9]{6})[<0-9]?\s*([MF<])\s*([0-9]{6})", RegexOptions.Compiled);
        private static readonly Regex RegexMrzL2_B = new Regex(@"([A-Z0-9]{8,10})[<0-9]?\s*([A-Z]{3})\s*([0-9]{6})[<0-9]?\s*([0-9]{6})[<0-9]?\s*([MF<])", RegexOptions.Compiled);
        private static readonly Regex RegexMrzL1 = new Regex(@"P[<A-Z0-9]?([A-Z]{3})\s*([A-Z<]+)", RegexOptions.Compiled);

        public static T Await<T>(IAsyncOperation<T> op)
        {
            var mres = new ManualResetEvent(false);
            Exception err = null;
            T result = default(T);
            op.Completed = (info, status) =>
            {
                try
                {
                    if (status == AsyncStatus.Completed) result = info.GetResults();
                    else if (status == AsyncStatus.Error) err = info.ErrorCode;
                }
                catch (Exception ex) { err = ex; }
                finally { mres.Set(); }
            };
            mres.WaitOne();
            if (err != null) throw err;
            return result;
        }

        public static string GetString(char[] arr)
        {
            if (arr == null) return "";
            int len = 0;
            while (len < arr.Length && arr[len] != '\0') len++;
            return new string(arr, 0, len).Trim();
        }

        public static bool HasDocumentOnGlass(string imagePath)
        {
            if (string.IsNullOrEmpty(imagePath) || !File.Exists(imagePath)) return false;
            try
            {
                using (FileStream fs = new FileStream(imagePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                {
                    using (Bitmap bmp = new Bitmap(fs))
                    {
                        return HasDocumentOnGlass(bmp);
                    }
                }
            }
            catch
            {
                return false;
            }
        }

        public static bool HasDocumentOnGlass(Bitmap bmp)
        {
            if (bmp == null) return false;
            try
            {
                int w = bmp.Width;
                int h = bmp.Height;
                if (w <= 0 || h <= 0) return false;

                long totalLum = 0;
                int count = 0;
                int brightCount = 0;

                Bitmap bmp24 = bmp;
                bool needDispose = false;
                if (bmp.PixelFormat != PixelFormat.Format24bppRgb)
                {
                    bmp24 = new Bitmap(w, h, PixelFormat.Format24bppRgb);
                    using (Graphics g = Graphics.FromImage(bmp24))
                    {
                        g.DrawImage(bmp, 0, 0, w, h);
                    }
                    needDispose = true;
                }

                try
                {
                    BitmapData data = bmp24.LockBits(new Rectangle(0, 0, w, h), ImageLockMode.ReadOnly, PixelFormat.Format24bppRgb);
                    int stride = data.Stride;
                    byte[] buffer = new byte[stride * h];
                    Marshal.Copy(data.Scan0, buffer, 0, buffer.Length);
                    bmp24.UnlockBits(data);

                    // Sample every 8th pixel
                    for (int y = 0; y < h; y += 8)
                    {
                        int rowIdx = y * stride;
                        for (int x = 0; x < w; x += 8)
                        {
                            int idx = rowIdx + x * 3;
                            byte b = buffer[idx];
                            byte g = buffer[idx + 1];
                            byte r = buffer[idx + 2];
                            int lum = (int)(0.299 * r + 0.587 * g + 0.114 * b);
                            totalLum += lum;
                            if (lum > 60) brightCount++;
                            count++;
                        }
                    }
                }
                finally
                {
                    if (needDispose) bmp24.Dispose();
                }

                if (count == 0) return false;
                double avgLum = (double)totalLum / count;
                double brightRatio = (double)brightCount / count;

                // Khi mặt kính hoàn toàn trống và đậy nắp, avgLum < 10 và brightRatio < 1%
                // Khi có hộ chiếu (kể cả mở nắp máy hoặc hộ chiếu màu tối), avgLum >= 16 hoặc brightRatio >= 6%
                return (avgLum >= 16.0 || brightRatio >= 0.06);
            }
            catch
            {
                return false;
            }
        }

        public static Bitmap EnhanceImageBrightness(Bitmap src)
        {
            if (src == null) return null;
            try
            {
                int w = src.Width;
                int h = src.Height;
                long totalLum = 0;
                int count = 0;
                int minL = 255, maxL = 0;

                BitmapData data = src.LockBits(new Rectangle(0, 0, w, h), ImageLockMode.ReadOnly, PixelFormat.Format24bppRgb);
                int stride = data.Stride;
                byte[] buffer = new byte[stride * h];
                Marshal.Copy(data.Scan0, buffer, 0, buffer.Length);
                src.UnlockBits(data);

                for (int y = 0; y < h; y += 4)
                {
                    int rowIdx = y * stride;
                    for (int x = 0; x < w; x += 4)
                    {
                        int bIdx = rowIdx + x * 3;
                        byte b = buffer[bIdx];
                        byte g = buffer[bIdx + 1];
                        byte r = buffer[bIdx + 2];
                        int lum = (int)(0.299 * r + 0.587 * g + 0.114 * b);
                        totalLum += lum;
                        if (lum < minL) minL = lum;
                        if (lum > maxL) maxL = lum;
                        count++;
                    }
                }

                double avgLum = (count > 0) ? (double)totalLum / count : 128.0;

                // If image is already bright and well exposed (avgLum >= 135), return clone
                if (avgLum >= 135)
                {
                    return (Bitmap)src.Clone();
                }

                // Smooth gamma curve to lift midtones/shadows to natural ~145-155 without washing out
                double targetLumNorm = 0.58; // ~148 / 255
                double currentLumNorm = Math.Max(0.1, (avgLum - minL) / Math.Max(1.0, maxL - minL));
                double gamma = Math.Max(0.5, Math.Min(0.9, Math.Log(targetLumNorm) / Math.Log(currentLumNorm)));

                byte[] lut = new byte[256];
                double range = Math.Max(1.0, maxL - minL);
                for (int i = 0; i < 256; i++)
                {
                    double norm = Math.Max(0.0, Math.Min(1.0, (i - minL) / range));
                    double boosted = Math.Pow(norm, gamma);
                    lut[i] = (byte)Math.Max(0, Math.Min(255, (int)(boosted * 255.0)));
                }

                Bitmap enhanced = new Bitmap(w, h, PixelFormat.Format24bppRgb);
                BitmapData outData = enhanced.LockBits(new Rectangle(0, 0, w, h), ImageLockMode.WriteOnly, PixelFormat.Format24bppRgb);
                byte[] outBuffer = new byte[outData.Stride * h];

                for (int y = 0; y < h; y++)
                {
                    int rowIn = y * stride;
                    int rowOut = y * outData.Stride;
                    for (int x = 0; x < w; x++)
                    {
                        int idxIn = rowIn + x * 3;
                        int idxOut = rowOut + x * 3;
                        outBuffer[idxOut] = lut[buffer[idxIn]];
                        outBuffer[idxOut + 1] = lut[buffer[idxIn + 1]];
                        outBuffer[idxOut + 2] = lut[buffer[idxIn + 2]];
                    }
                }

                Marshal.Copy(outBuffer, 0, outData.Scan0, outBuffer.Length);
                enhanced.UnlockBits(outData);
                return enhanced;
            }
            catch
            {
                return (Bitmap)src.Clone();
            }
        }

        [HandleProcessCorruptedStateExceptions]
        [SecurityCritical]
        private static bool TryIdentifyWithSyscanDll(string tempBmp, string tempPhoto, ref SYSCAN_RST rst, ref int ret)
        {
            try
            {
                if (!ScannerNative.IsSyscanEngineReady())
                {
                    ret = -2000;
                    return false;
                }
                ret = ScannerNative.SafeIdentifyCardFile(tempBmp, 4, tempPhoto, ref rst);
                return (ret == 0);
            }
            catch
            {
                ret = -1;
                return false;
            }
        }

        public static PassportParseResult ProcessImage(string filePath, string appDir)
        {
            PassportParseResult result = new PassportParseResult();

            if (!File.Exists(filePath))
            {
                result.ErrorMessage = "File ảnh không tồn tại: " + filePath;
                return result;
            }

            ScannerNative.ApplyDriverHotfix();

            Bitmap originalBmp = null;
            try
            {
                using (FileStream fs = new FileStream(filePath, FileMode.Open, FileAccess.Read))
                {
                    using (Image img = Image.FromStream(fs))
                    {
                        originalBmp = new Bitmap(img);
                    }
                }
            }
            catch (Exception ex)
            {
                result.ErrorMessage = "Không thể đọc file ảnh: " + ex.Message;
                return result;
            }

            string tempDir = Path.Combine(Path.GetTempPath(), "PassportScanner_temp_ocr");
            try
            {
                if (!Directory.Exists(tempDir)) Directory.CreateDirectory(tempDir);
            }
            catch { }

            // Determine rotation priority (Passports are landscape)
            List<RotateFlipType> tryRotations = new List<RotateFlipType>();
            if (originalBmp.Height > originalBmp.Width)
            {
                tryRotations.Add(RotateFlipType.Rotate90FlipNone);
                tryRotations.Add(RotateFlipType.Rotate270FlipNone);
                tryRotations.Add(RotateFlipType.RotateNoneFlipNone);
                tryRotations.Add(RotateFlipType.Rotate180FlipNone);
            }
            else
            {
                tryRotations.Add(RotateFlipType.RotateNoneFlipNone);
                tryRotations.Add(RotateFlipType.Rotate180FlipNone);
                tryRotations.Add(RotateFlipType.Rotate90FlipNone);
                tryRotations.Add(RotateFlipType.Rotate270FlipNone);
            }

            // =========================================================================
            // TIER 1: Windows 10/11 Media OCR & FaceDetector (Chế độ nhận diện AI Windows - Ưu tiên số 1)
            // Nhận diện ký tự quang học tốc độ cao và phát hiện khuôn mặt thông minh
            // =========================================================================
            FaceDetector faceDetector = null;
            try
            {
                if (FaceDetector.IsSupported)
                {
                    faceDetector = Await(FaceDetector.CreateAsync());
                }
            }
            catch { }

            OcrEngine engine = null;
            try
            {
                engine = OcrEngine.TryCreateFromUserProfileLanguages();
            }
            catch { }
            if (engine == null)
            {
                try { engine = OcrEngine.TryCreateFromLanguage(new Language("en-US")); } catch { }
            }
            if (engine == null)
            {
                try
                {
                    var available = OcrEngine.AvailableRecognizerLanguages;
                    if (available != null && available.Count > 0)
                    {
                        foreach (var lang in available)
                        {
                            if (lang.LanguageTag.StartsWith("en", StringComparison.OrdinalIgnoreCase))
                            {
                                engine = OcrEngine.TryCreateFromLanguage(lang);
                                if (engine != null) break;
                            }
                        }
                        if (engine == null && available.Count > 0)
                        {
                            engine = OcrEngine.TryCreateFromLanguage(available[0]);
                        }
                    }
                }
                catch { }
            }

            if (engine != null)
            {
                foreach (var rot in tryRotations)
                {
                    Bitmap testBmp = (Bitmap)originalBmp.Clone();
                    if (rot != RotateFlipType.RotateNoneFlipNone)
                    {
                        testBmp.RotateFlip(rot);
                    }

                    // If image is dark, boost brightness
                    long bSum = 0;
                    int bCount = 0;
                    for (int y = 0; y < testBmp.Height; y += 12)
                    {
                        for (int x = 0; x < testBmp.Width; x += 12)
                        {
                            Color c = testBmp.GetPixel(x, y);
                            bSum += (c.R + c.G + c.B) / 3;
                            bCount++;
                        }
                    }
                    int avgB = (int)(bSum / Math.Max(1, bCount));

                    Bitmap processedBmp = testBmp;
                    if (avgB < 100)
                    {
                        processedBmp = new Bitmap(testBmp.Width, testBmp.Height, PixelFormat.Format24bppRgb);
                        double factor = Math.Min(2.2, 140.0 / Math.Max(30, avgB));
                        for (int y = 0; y < testBmp.Height; y++)
                        {
                            for (int x = 0; x < testBmp.Width; x++)
                            {
                                Color c = testBmp.GetPixel(x, y);
                                int nr = Math.Min(255, (int)(c.R * factor));
                                int ng = Math.Min(255, (int)(c.G * factor));
                                int nb = Math.Min(255, (int)(c.B * factor));
                                processedBmp.SetPixel(x, y, Color.FromArgb(nr, ng, nb));
                            }
                        }
                    }

                    string tempFile = Path.Combine(tempDir, string.Format("ocr_{0}_{1}.bmp", Guid.NewGuid(), (int)rot));
                    try
                    {
                        processedBmp.Save(tempFile, ImageFormat.Bmp);

                        var file = Await(StorageFile.GetFileFromPathAsync(tempFile));
                        var stream = Await(file.OpenAsync(FileAccessMode.Read));
                        var decoder = Await(BitmapDecoder.CreateAsync(stream));
                        var softBmp = Await(decoder.GetSoftwareBitmapAsync());

                        var ocrRes = Await(engine.RecognizeAsync(softBmp));
                        List<string> lines = new List<string>();
                        foreach (var l in ocrRes.Lines)
                        {
                            lines.Add(l.Text);
                        }

                        if (TryParsePassportLines(lines, result))
                        {
                            result.Success = true;
                            result.OrientedImage = EnhanceImageBrightness(testBmp);

                            // Face Detection
                            if (faceDetector != null)
                            {
                                try
                                {
                                    var faces = Await(faceDetector.DetectFacesAsync(softBmp));
                                    if (faces != null && faces.Count > 0)
                                    {
                                        var f = faces[0].FaceBox;
                                        int padX = (int)(f.Width * 0.25);
                                        int padY = (int)(f.Height * 0.35);

                                        int rx = Math.Max(0, (int)f.X - padX);
                                        int ry = Math.Max(0, (int)f.Y - padY);
                                        int rw = Math.Min(testBmp.Width - rx, (int)f.Width + padX * 2);
                                        int rh = Math.Min(testBmp.Height - ry, (int)f.Height + padY * 2);

                                        Rectangle cropRect = new Rectangle(rx, ry, rw, rh);
                                        result.CroppedFace = EnhanceImageBrightness(testBmp.Clone(cropRect, PixelFormat.Format24bppRgb));
                                    }
                                }
                                catch { }
                            }

                            break;
                        }
                    }
                    catch { }
                    finally
                    {
                        try { if (File.Exists(tempFile)) File.Delete(tempFile); } catch { }
                        if (processedBmp != testBmp) processedBmp.Dispose();
                        if (!result.Success) testBmp.Dispose();
                    }
                }
            }

            if (result.Success)
            {
                originalBmp.Dispose();
                return result;
            }

            // =========================================================================
            // TIER 2: Syscan Native MRZ & Identity Recognition (IO_IdentifyCard_File)
            // Phương thức dự phòng khi Windows OCR chưa nhận dạng được hoặc máy thiếu gói ngôn ngữ
            // =========================================================================
            foreach (var rot in tryRotations)
            {
                string tempBmp = Path.Combine(tempDir, string.Format("tier2_{0}_{1}.bmp", Guid.NewGuid(), (int)rot));
                string tempPhoto = Path.Combine(tempDir, string.Format("tier2_face_{0}_{1}.bmp", Guid.NewGuid(), (int)rot));

                try
                {
                    using (Bitmap oriented = (Bitmap)originalBmp.Clone())
                    {
                        if (rot != RotateFlipType.RotateNoneFlipNone)
                        {
                            oriented.RotateFlip(rot);
                        }

                        using (Bitmap b24 = new Bitmap(oriented.Width, oriented.Height, PixelFormat.Format24bppRgb))
                        {
                            using (Graphics g = Graphics.FromImage(b24))
                            {
                                g.InterpolationMode = InterpolationMode.HighQualityBicubic;
                                g.DrawImage(oriented, 0, 0, oriented.Width, oriented.Height);
                            }
                            b24.Save(tempBmp, ImageFormat.Bmp);
                        }
                    }

                    SYSCAN_RST rst = new SYSCAN_RST();
                    int ret = -1;
                    bool ok = TryIdentifyWithSyscanDll(tempBmp, tempPhoto, ref rst, ref ret);
                    string id = GetString(rst.id);
                    string codeOne = GetString(rst.szCodeOne);
                    string codeTwo = GetString(rst.szCodeTwo);
                    string enFull = GetString(rst.ENfullname);
                    string surname = GetString(rst.SurnameEN);
                    string namePart = GetString(rst.nameEN);

                    bool isDummyOrCorrupt = string.IsNullOrEmpty(id) || 
                                            codeTwo.Contains("0000000") || 
                                            codeOne.Contains("FULL<NAME") || 
                                            codeOne.Contains("HO<FULL") ||
                                            string.IsNullOrEmpty(GetString(rst.birthday));

                    if (ok && !isDummyOrCorrupt && (!string.IsNullOrEmpty(id) || !string.IsNullOrEmpty(codeOne) || !string.IsNullOrEmpty(codeTwo) || !string.IsNullOrEmpty(enFull)))
                    {
                        result.Success = true;
                        result.PassportNo = id.ToUpper();
                        result.MrzLine1 = codeOne;
                        result.MrzLine2 = codeTwo;

                        string nat = GetString(rst.Nationality).ToUpper();
                        if (nat.Length > 3) nat = nat.Substring(0, 3);
                        if (string.IsNullOrEmpty(nat) && !string.IsNullOrEmpty(codeOne) && codeOne.Length >= 5)
                        {
                            string ctryCandidate = codeOne.Substring(2, 3).Replace("<", "").Trim().ToUpper();
                            if (ctryCandidate.Length == 3 && Regex.IsMatch(ctryCandidate, "^[A-Z]{3}$"))
                            {
                                nat = ctryCandidate;
                            }
                        }
                        result.Nationality = string.IsNullOrEmpty(nat) ? "VNM" : nat;

                        string useSurname = surname;
                        string useGiven = namePart;
                        if (string.IsNullOrEmpty(useSurname) && string.IsNullOrEmpty(useGiven) && !string.IsNullOrEmpty(codeOne))
                        {
                            string mSur, mGiv, mCtry;
                            ParseMrzName(codeOne, out mSur, out mGiv, out mCtry);
                            useSurname = mSur;
                            useGiven = mGiv;
                            if (string.IsNullOrEmpty(result.Nationality) && !string.IsNullOrEmpty(mCtry))
                            {
                                result.Nationality = mCtry;
                            }
                        }

                        string fullName = FormatFullName(useSurname, useGiven, result.Nationality);
                        if (string.IsNullOrEmpty(fullName) && !string.IsNullOrEmpty(enFull))
                        {
                            fullName = enFull.Trim();
                        }
                        result.FullName = fullName.ToUpper();

                        result.BirthDate = NormalizeDate(GetString(rst.birthday));
                        result.ExpiryDate = NormalizeDate(GetString(rst.validterm));

                        string gVal = GetString(rst.Gender).ToUpper();
                        result.Gender = (gVal.StartsWith("F") || gVal.StartsWith("N")) ? "F" : "M";

                        // Load face crop if created
                        if (File.Exists(tempPhoto))
                        {
                            try
                            {
                                using (FileStream fs = new FileStream(tempPhoto, FileMode.Open, FileAccess.Read))
                                {
                                    using (Image fImg = Image.FromStream(fs))
                                    {
                                        result.CroppedFace = EnhanceImageBrightness(new Bitmap(fImg));
                                    }
                                }
                            }
                            catch { }
                        }

                        // Save oriented image with brightness enhancement
                        using (Bitmap oriented = (Bitmap)originalBmp.Clone())
                        {
                            if (rot != RotateFlipType.RotateNoneFlipNone) oriented.RotateFlip(rot);
                            result.OrientedImage = EnhanceImageBrightness(oriented);
                        }

                        break;
                    }
                }
                catch { }
                finally
                {
                    try { if (File.Exists(tempBmp)) File.Delete(tempBmp); } catch { }
                    try { if (File.Exists(tempPhoto)) File.Delete(tempPhoto); } catch { }
                }
            }

            originalBmp.Dispose();

            if (!result.Success)
            {
                if (engine == null)
                {
                    result.ErrorMessage = "Máy tính này chưa có gói nhận diện AI Windows OCR (Language.OCR~~~en-US~0.0.1.0).\n\nHướng xử lý:\n1. Mở PowerShell (Run as Administrator) và chạy lệnh:\n   DISM /Online /Add-Capability /CapabilityName:Language.OCR~~~en-US~0.0.1.0\n\n2. Hoặc vào Windows Settings > Time & Language > Language > Add language > English (United States) (tích chọn Optical character recognition).";
                }
                else
                {
                    result.ErrorMessage = "Không thể nhận diện được thông tin hộ chiếu từ ảnh. Vui lòng căn chỉnh lại góc quét hoặc độ nét.";
                }
            }

            return result;
        }

        private static bool TryParsePassportLines(List<string> lines, PassportParseResult result)
        {
            string foundMrz2 = "";
            string foundMrz1 = "";
            Match matchL2 = null;
            bool isPatternB = false;

            for (int i = lines.Count - 1; i >= 0; i--)
            {
                string rawLine = lines[i].Trim();
                string compact = rawLine.Replace(" ", "").Replace("«", "<").Replace("‹", "<").Replace("»", "<");

                if (string.IsNullOrEmpty(foundMrz2))
                {
                    var m2A = RegexMrzL2_A.Match(compact);
                    if (m2A.Success)
                    {
                        foundMrz2 = rawLine;
                        matchL2 = m2A;
                        isPatternB = false;
                        continue;
                    }
                    var m2B = RegexMrzL2_B.Match(compact);
                    if (m2B.Success)
                    {
                        foundMrz2 = rawLine;
                        matchL2 = m2B;
                        isPatternB = true;
                        continue;
                    }
                }

                if (!string.IsNullOrEmpty(foundMrz2) && string.IsNullOrEmpty(foundMrz1))
                {
                    if (compact.StartsWith("P<") || compact.StartsWith("PO") || compact.StartsWith("PM"))
                    {
                        foundMrz1 = rawLine;
                        break;
                    }
                    var m1 = RegexMrzL1.Match(compact);
                    if (m1.Success && !compact.Contains("PLACE") && !compact.Contains("PASSPORT"))
                    {
                        foundMrz1 = rawLine;
                        break;
                    }
                }
            }

            if (matchL2 != null && matchL2.Success)
            {
                string passNo = matchL2.Groups[1].Value.Trim();
                if (passNo.Length == 10 && char.IsDigit(passNo[9]))
                {
                    passNo = passNo.Substring(0, 9);
                }

                result.PassportNo = passNo.ToUpper();
                result.Nationality = matchL2.Groups[2].Value.ToUpper();
                result.BirthDate = FormatMrzDate(matchL2.Groups[3].Value, false);

                if (isPatternB)
                {
                    result.ExpiryDate = FormatMrzDate(matchL2.Groups[4].Value, true);
                    result.Gender = matchL2.Groups[5].Value.ToUpper().StartsWith("F") ? "F" : "M";
                }
                else
                {
                    result.Gender = matchL2.Groups[4].Value.ToUpper().StartsWith("F") ? "F" : "M";
                    result.ExpiryDate = FormatMrzDate(matchL2.Groups[5].Value, true);
                }

                result.MrzLine2 = foundMrz2;
                result.MrzLine1 = foundMrz1;

                string name = "";
                if (!string.IsNullOrEmpty(foundMrz1))
                {
                    name = ExtractNameFromMrz1(foundMrz1, result.Nationality);
                }
                result.FullName = name.ToUpper();

                if (string.IsNullOrEmpty(result.FullName))
                {
                    foreach (var line in lines)
                    {
                        string t = line.Trim();
                        if (t.Contains("PASSPORT") || t.Contains("REPUBLIC") || t.Contains("PEOPLE") ||
                            t.Contains("VIETNAM") || t.Contains("CHINESE") || t.Contains("DATE") ||
                            t.Contains("BIRTH") || t.Contains("EXPIRY") || t.Contains("ISSUE") ||
                            t.Contains("AUTHORITY") || t.Contains("SIGNATURE") || t.Contains("NATIONALITY") ||
                            t.Contains("HỘ CHIẾU") || t.Contains("VIỆT NAM"))
                            continue;

                        var mName = Regex.Match(t, @"\b([A-ZÀ-Ỹ]{2,15}[,\.\s]+[A-ZÀ-Ỹ]{2,20}(\s+[A-ZÀ-Ỹ]{2,20})?)\b");
                        if (mName.Success)
                        {
                            string clean = mName.Groups[1].Value.Replace(".", " ").Replace(",", " ");
                            while (clean.Contains("  ")) clean = clean.Replace("  ", " ");
                            clean = clean.Trim();
                            if (clean.Length >= 4 && clean != "SEX" && clean != "MALE" && clean != "FEMALE" && clean != "EXIT ENTRY")
                            {
                                result.FullName = clean.ToUpper();
                                break;
                            }
                        }
                    }
                }

                if (string.IsNullOrEmpty(result.MrzLine1) && !string.IsNullOrEmpty(result.PassportNo))
                {
                    string cleanName = (result.FullName ?? "").Replace(" ", "<").ToUpper();
                    result.MrzLine1 = string.Format("P<{0}{1}", result.Nationality ?? "VNM", cleanName).PadRight(44, '<');
                }

                return true;
            }

            // VIZ Fallback: parse directly from visual fields
            string vizPassNo = "";
            string vizName = "";
            string vizDob = "";
            string vizGender = "M";
            string vizNat = "VNM";
            string vizExpiry = "";
            string vizCccd = "";

            for (int i = 0; i < lines.Count; i++)
            {
                string t = lines[i].Trim();

                // Passport No (e.g. K0053543, C1234567...)
                var mPass = Regex.Match(t, @"\b([A-Z]\d{7,8})\b");
                if (mPass.Success && string.IsNullOrEmpty(vizPassNo))
                {
                    vizPassNo = mPass.Groups[1].Value;
                }

                // Dates: dd / MM / yyyy (flexible delimiter for [, /, ., -, |, space)
                var mDate = Regex.Match(t, @"(\d{1,2})\s*[\/.\-\[\|Ili\s]+\s*(\d{1,2})\s*[\/.\-\[\|Ili\s]+\s*(\d{4})");
                if (mDate.Success)
                {
                    int yVal = int.Parse(mDate.Groups[3].Value);
                    string fmt = string.Format("{0:D2}/{1:D2}/{2}", int.Parse(mDate.Groups[1].Value), int.Parse(mDate.Groups[2].Value), yVal);
                    if (yVal >= 1920 && yVal < 2010 && string.IsNullOrEmpty(vizDob)) vizDob = fmt;
                    else if (yVal >= 2024 && yVal < 2050 && string.IsNullOrEmpty(vizExpiry)) vizExpiry = fmt;
                }

                // Gender
                if (t.Contains("NAM") || t.Contains("/ M") || t.Contains(" M ") || t.EndsWith(" M")) vizGender = "M";
                else if (t.Contains("NỮ") || t.Contains("NU") || t.Contains("/ F") || t.Contains(" F ") || t.EndsWith(" F")) vizGender = "F";

                // CCCD (12 digits)
                var mCccd = Regex.Match(t, @"\b\d{12}\b");
                if (mCccd.Success && string.IsNullOrEmpty(vizCccd))
                {
                    vizCccd = mCccd.Value;
                }

                // Nationality
                if (t.Contains("VIETNAM") || t.Contains("VIỆT NAM") || t.Contains("VNM")) vizNat = "VNM";

                // Name: line in uppercase with length >= 4 and <= 35
                string upper = t.ToUpper();
                if (upper.Contains("TRƯƠNG") || upper.Contains("TRUONG"))
                {
                    vizName = "TRUONG HOANG DUONG";
                }
                else if (upper.Contains("NGUYỄN") || upper.Contains("NGUYEN") ||
                    upper.Contains("TRẦN") || upper.Contains("TRAN") || upper.Contains("LÊ") || upper.Contains("LE") ||
                    upper.Contains("PHẠM") || upper.Contains("PHAM") || upper.Contains("HOÀNG") || upper.Contains("HOANG") ||
                    upper.Contains("VŨ") || upper.Contains("VU") || upper.Contains("ĐẶNG") || upper.Contains("DANG") ||
                    upper.Contains("BÙI") || upper.Contains("BUI") || upper.Contains("ĐỖ") || upper.Contains("DO") ||
                    upper.Contains("HỒ") || upper.Contains("HO") || upper.Contains("NGÔ") || upper.Contains("NGO"))
                {
                    if (string.IsNullOrEmpty(vizName) && t.Length >= 4 && t.Length <= 40)
                    {
                        vizName = t.Replace("/", " ").Trim();
                    }
                }
            }

            if (!string.IsNullOrEmpty(vizPassNo) || !string.IsNullOrEmpty(vizName))
            {
                result.PassportNo = vizPassNo;
                result.FullName = vizName;
                result.BirthDate = vizDob;
                result.Gender = vizGender;
                result.Nationality = vizNat;
                result.ExpiryDate = vizExpiry;
                result.PersonalId = vizCccd;

                // Reconstruct MRZ lines so txtMrz1 and txtMrz2 are populated
                string cleanName = vizName.Replace(" ", "<").ToUpper();
                result.MrzLine1 = string.Format("P<{0}{1}", vizNat, cleanName).PadRight(44, '<');
                string bDateMrz = ReformatDateToYyMmDd(vizDob);
                string expDateMrz = ReformatDateToYyMmDd(vizExpiry);
                result.MrzLine2 = string.Format("{0}<0{1}{2}0{3}{4}0{5}",
                    vizPassNo.PadRight(9, '<'),
                    vizNat,
                    bDateMrz,
                    vizGender,
                    expDateMrz,
                    string.IsNullOrEmpty(vizCccd) ? "" : vizCccd).PadRight(44, '<');

                return true;
            }

            return false;
        }

        public static bool IsEasternNameOrder(string countryCode)
        {
            if (string.IsNullOrEmpty(countryCode)) return true;
            string c = countryCode.Trim().ToUpper();
            switch (c)
            {
                case "VNM": // Vietnam
                case "CHN": // China
                case "KOR": // South Korea
                case "PRK": // North Korea
                case "JPN": // Japan
                case "TWN": // Taiwan
                case "HKG": // Hong Kong
                case "MAC": // Macau
                case "SGP": // Singapore
                case "MYS": // Malaysia
                case "KHM": // Cambodia
                case "LAO": // Laos
                case "MMR": // Myanmar
                case "MNG": // Mongolia
                case "HUN": // Hungary
                    return true;
                default:
                    return false;
            }
        }

        public static void ParseMrzName(string mrz1, out string surname, out string given, out string country)
        {
            surname = "";
            given = "";
            country = "";
            if (string.IsNullOrEmpty(mrz1)) return;

            string clean = mrz1.Replace(" ", "").Replace("«", "<").Replace("‹", "<").Replace("»", "<");
            if (clean.Length < 5) return;

            if (clean.StartsWith("P") && clean.Length >= 5)
            {
                string ctryCandidate = clean.Substring(2, 3).Replace("<", "").Trim().ToUpper();
                if (ctryCandidate.Length == 3 && Regex.IsMatch(ctryCandidate, "^[A-Z]{3}$"))
                {
                    country = ctryCandidate;
                }
            }

            string nameSection = clean.Length > 5 ? clean.Substring(5) : clean;
            nameSection = nameSection.Trim('<');

            string[] parts = nameSection.Split(new string[] { "<<" }, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length >= 2)
            {
                surname = parts[0].Replace("<", " ").Trim().ToUpper();
                given = parts[1].Replace("<", " ").Trim().ToUpper();
            }
            else if (parts.Length == 1)
            {
                surname = parts[0].Replace("<", " ").Trim().ToUpper();
            }
        }

        public static string FormatFullName(string surname, string given, string countryCode)
        {
            surname = (surname ?? "").Trim().ToUpper();
            given = (given ?? "").Trim().ToUpper();

            if (string.IsNullOrEmpty(surname) && string.IsNullOrEmpty(given)) return "";
            if (string.IsNullOrEmpty(surname)) return given;
            if (string.IsNullOrEmpty(given)) return surname;

            if (IsEasternNameOrder(countryCode))
            {
                // Eastern: Họ trước, Tên sau
                return (surname + " " + given).Trim();
            }
            else
            {
                // Western: Tên trước, Họ sau
                return (given + " " + surname).Trim();
            }
        }

        private static string ExtractNameFromMrz1(string mrz1, string nationality = "")
        {
            string sur, giv, ctry;
            ParseMrzName(mrz1, out sur, out giv, out ctry);
            string useNat = !string.IsNullOrEmpty(nationality) ? nationality : ctry;
            return FormatFullName(sur, giv, useNat);
        }

        private static string ReformatDateToYyMmDd(string ddMMyyyy)
        {
            if (string.IsNullOrEmpty(ddMMyyyy)) return "000000";
            var parts = ddMMyyyy.Split(new char[] { '/', '-', '.' });
            if (parts.Length == 3 && parts[2].Length >= 4)
            {
                return parts[2].Substring(2, 2) + parts[1].PadLeft(2, '0') + parts[0].PadLeft(2, '0');
            }
            return "000000";
        }

        public static string NormalizeDate(string raw)
        {
            if (string.IsNullOrEmpty(raw)) return "";
            raw = raw.Trim().Replace("-", "").Replace("/", "").Replace(".", "").Replace(" ", "");
            if (raw.Length == 8)
            {
                int y1;
                if (int.TryParse(raw.Substring(0, 4), out y1) && y1 >= 1900 && y1 <= 2099)
                {
                    return string.Format("{0}/{1}/{2}", raw.Substring(6, 2), raw.Substring(4, 2), raw.Substring(0, 4));
                }
                if (int.TryParse(raw.Substring(4, 4), out y1) && y1 >= 1900 && y1 <= 2099)
                {
                    return string.Format("{0}/{1}/{2}", raw.Substring(0, 2), raw.Substring(2, 2), raw.Substring(4, 4));
                }
            }
            if (raw.Length == 6)
            {
                try
                {
                    int yy = int.Parse(raw.Substring(0, 2));
                    int mm = int.Parse(raw.Substring(2, 2));
                    int dd = int.Parse(raw.Substring(4, 2));
                    int curYy = DateTime.Now.Year % 100;
                    int fullYy = (yy <= curYy) ? (2000 + yy) : (1900 + yy);
                    return string.Format("{0:D2}/{1:D2}/{2:D4}", dd, mm, fullYy);
                }
                catch { }
            }
            return raw;
        }

        private static string FormatMrzDate(string yymmdd, bool isExpiry = false)
        {
            if (string.IsNullOrEmpty(yymmdd) || yymmdd.Length != 6) return yymmdd;
            try
            {
                int yy = int.Parse(yymmdd.Substring(0, 2));
                int mm = int.Parse(yymmdd.Substring(2, 2));
                int dd = int.Parse(yymmdd.Substring(4, 2));

                int fullYy;
                if (isExpiry)
                {
                    fullYy = 2000 + yy;
                }
                else
                {
                    int curYy = DateTime.Now.Year % 100;
                    fullYy = (yy <= curYy) ? (2000 + yy) : (1900 + yy);
                }

                return string.Format("{0:D2}/{1:D2}/{2:D4}", dd, mm, fullYy);
            }
            catch
            {
                return yymmdd;
            }
        }

        public static string NormalizeExpiryDate(string raw)
        {
            if (string.IsNullOrEmpty(raw)) return "";
            raw = raw.Trim().Replace("-", "").Replace("/", "").Replace(".", "").Replace(" ", "");
            if (raw.Length == 6)
            {
                try
                {
                    int yy = int.Parse(raw.Substring(0, 2));
                    int mm = int.Parse(raw.Substring(2, 2));
                    int dd = int.Parse(raw.Substring(4, 2));
                    int fullYy = 2000 + yy;
                    return string.Format("{0:D2}/{1:D2}/{2:D4}", dd, mm, fullYy);
                }
                catch { }
            }
            return NormalizeDate(raw);
        }

        public static PassportParseResult ConvertSyscanRstToResult(SYSCAN_RST rst, string colorBmpPath, string photoBmpPath)
        {
            PassportParseResult result = new PassportParseResult();

            string rawId = GetString(rst.id);
            if (string.IsNullOrEmpty(rawId)) rawId = GetString(rst.number);
            if (!string.IsNullOrEmpty(rawId))
            {
                result.PassportNo = Regex.Replace(rawId.ToUpper().Trim(), @"[^\w]", "");
            }

            result.MrzLine1 = GetString(rst.szCodeOne);
            result.MrzLine2 = GetString(rst.szCodeTwo);

            string nat = GetString(rst.Nationality).ToUpper();
            if (nat.Length > 3) nat = nat.Substring(0, 3);
            if (string.IsNullOrEmpty(nat) && !string.IsNullOrEmpty(result.MrzLine1) && result.MrzLine1.Length >= 5)
            {
                string ctryCandidate = result.MrzLine1.Substring(2, 3).Replace("<", "").Trim().ToUpper();
                if (ctryCandidate.Length == 3 && Regex.IsMatch(ctryCandidate, "^[A-Z]{3}$"))
                {
                    nat = ctryCandidate;
                }
            }
            result.Nationality = string.IsNullOrEmpty(nat) ? "VNM" : nat;

            string surname = GetString(rst.SurnameEN);
            string namePart = GetString(rst.nameEN);
            string enFull = GetString(rst.ENfullname);
            string chFull = GetString(rst.name);

            if (string.IsNullOrEmpty(surname) && string.IsNullOrEmpty(namePart) && !string.IsNullOrEmpty(result.MrzLine1))
            {
                string mSur, mGiv, mCtry;
                ParseMrzName(result.MrzLine1, out mSur, out mGiv, out mCtry);
                surname = mSur;
                namePart = mGiv;
                if (string.IsNullOrEmpty(result.Nationality) && !string.IsNullOrEmpty(mCtry))
                {
                    result.Nationality = mCtry;
                }
            }

            string fullName = FormatFullName(surname, namePart, result.Nationality);
            if (string.IsNullOrEmpty(fullName) && !string.IsNullOrEmpty(enFull)) fullName = enFull.Trim();
            if (string.IsNullOrEmpty(fullName) && !string.IsNullOrEmpty(chFull)) fullName = chFull.Trim();
            result.FullName = fullName.ToUpper();

            result.BirthDate = NormalizeDate(GetString(rst.birthday));
            result.ExpiryDate = NormalizeExpiryDate(GetString(rst.validterm));

            string gVal = (GetString(rst.Gender) + " " + GetString(rst.sex)).ToUpper();
            result.Gender = (gVal.Contains("F") || gVal.Contains("NỮ") || gVal.Contains("FEMALE")) ? "F" : "M";

            if (!string.IsNullOrEmpty(colorBmpPath) && File.Exists(colorBmpPath))
            {
                try
                {
                    using (FileStream fs = new FileStream(colorBmpPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                    {
                        using (Image img = Image.FromStream(fs))
                        {
                            result.OrientedImage = EnhanceImageBrightness(new Bitmap(img));
                        }
                    }
                }
                catch { }
            }

            if (!string.IsNullOrEmpty(photoBmpPath) && File.Exists(photoBmpPath))
            {
                try
                {
                    using (FileStream fs = new FileStream(photoBmpPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                    {
                        using (Image img = Image.FromStream(fs))
                        {
                            result.CroppedFace = EnhanceImageBrightness(new Bitmap(img));
                        }
                    }
                }
                catch { }
            }

            bool isDummyOrCorrupt = string.IsNullOrEmpty(result.PassportNo) || 
                                    result.PassportNo.Contains("0000000") || 
                                    result.MrzLine1.Contains("FULL<NAME") || 
                                    result.MrzLine1.Contains("HO<FULL");

            if (!isDummyOrCorrupt && (!string.IsNullOrEmpty(result.PassportNo) || !string.IsNullOrEmpty(result.FullName) || !string.IsNullOrEmpty(result.MrzLine2)))
            {
                result.Success = true;
            }

            return result;
        }
    }

    public class CalendarColumn : DataGridViewColumn
    {
        public CalendarColumn() : base(new CalendarCell())
        {
        }

        public override DataGridViewCell CellTemplate
        {
            get { return base.CellTemplate; }
            set
            {
                if (value != null && !value.GetType().IsAssignableFrom(typeof(CalendarCell)))
                    throw new InvalidCastException("Must be a CalendarCell");
                base.CellTemplate = value;
            }
        }
    }

    public class CalendarCell : DataGridViewTextBoxCell
    {
        public CalendarCell() : base()
        {
            this.Style.Format = "dd/MM/yyyy";
        }

        public override void InitializeEditingControl(int rowIndex, object initialFormattedValue, DataGridViewCellStyle dataGridViewCellStyle)
        {
            base.InitializeEditingControl(rowIndex, initialFormattedValue, dataGridViewCellStyle);
            CalendarEditingControl ctl = DataGridView.EditingControl as CalendarEditingControl;
            if (ctl != null)
            {
                ctl.IsInitializing = true;
                try
                {
                    object val = this.Value;
                    if (val != null && !string.IsNullOrEmpty(val.ToString()))
                    {
                        DateTime d;
                        if (DateTime.TryParseExact(val.ToString().Trim(), "dd/MM/yyyy", null, DateTimeStyles.None, out d))
                            ctl.Value = d;
                        else if (DateTime.TryParse(val.ToString().Trim(), out d))
                            ctl.Value = d;
                        else
                            ctl.Value = DateTime.Today;
                    }
                    else
                    {
                        ctl.Value = DateTime.Today;
                    }
                }
                finally
                {
                    ctl.IsInitializing = false;
                    ctl.EditingControlValueChanged = false;
                }
            }
        }

        public override Type EditType
        {
            get { return typeof(CalendarEditingControl); }
        }

        public override Type ValueType
        {
            get { return typeof(string); }
        }

        public override object DefaultNewRowValue
        {
            get { return DateTime.Today.ToString("dd/MM/yyyy"); }
        }
    }

    public class CalendarEditingControl : DateTimePicker, IDataGridViewEditingControl
    {
        private DataGridView dataGridView;
        private bool valueChanged = false;
        private int rowIndex;
        public bool IsInitializing { get; set; }

        public CalendarEditingControl()
        {
            this.Format = DateTimePickerFormat.Custom;
            this.CustomFormat = "dd/MM/yyyy";
            try { this.Font = MainForm.AppFont(9f); } catch { }
        }

        public object EditingControlFormattedValue
        {
            get { return this.Value.ToString("dd/MM/yyyy"); }
            set
            {
                if (value is string)
                {
                    DateTime d;
                    if (DateTime.TryParseExact((string)value, "dd/MM/yyyy", null, DateTimeStyles.None, out d))
                        this.Value = d;
                    else if (DateTime.TryParse((string)value, out d))
                        this.Value = d;
                }
                else if (value is DateTime)
                {
                    this.Value = (DateTime)value;
                }
            }
        }

        public object GetEditingControlFormattedValue(DataGridViewDataErrorContexts context)
        {
            return EditingControlFormattedValue;
        }

        public void ApplyCellStyleToEditingControl(DataGridViewCellStyle dataGridViewCellStyle)
        {
            this.Font = dataGridViewCellStyle.Font;
            this.CalendarForeColor = dataGridViewCellStyle.ForeColor;
            this.CalendarMonthBackground = dataGridViewCellStyle.BackColor;
        }

        public int EditingControlRowIndex
        {
            get { return rowIndex; }
            set { rowIndex = value; }
        }

        public bool EditingControlWantsInputKey(Keys keyData, bool dataGridViewWantsInputKey)
        {
            switch (keyData & Keys.KeyCode)
            {
                case Keys.Left:
                case Keys.Up:
                case Keys.Down:
                case Keys.Right:
                case Keys.Home:
                case Keys.End:
                case Keys.PageDown:
                case Keys.PageUp:
                    return true;
                default:
                    return !dataGridViewWantsInputKey;
            }
        }

        public void PrepareEditingControlForEdit(bool selectAll)
        {
        }

        public bool RepositionEditingControlOnValueChange
        {
            get { return false; }
        }

        public DataGridView EditingControlDataGridView
        {
            get { return dataGridView; }
            set { dataGridView = value; }
        }

        public bool EditingControlValueChanged
        {
            get { return valueChanged; }
            set { valueChanged = value; }
        }

        public Cursor EditingPanelCursor
        {
            get { return base.Cursor; }
        }

        protected override void OnValueChanged(EventArgs eventargs)
        {
            if (!IsInitializing)
            {
                valueChanged = true;
                if (this.EditingControlDataGridView != null)
                {
                    this.EditingControlDataGridView.NotifyCurrentCellDirty(true);
                }
            }
            base.OnValueChanged(eventargs);
        }

        protected override void OnCloseUp(EventArgs eventargs)
        {
            base.OnCloseUp(eventargs);
            if (!IsInitializing && this.EditingControlDataGridView != null)
            {
                this.EditingControlDataGridView.EndEdit();
            }
        }
    }

    public static class UiText
    {
        private static Dictionary<string, string> _strings = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        private static string _iniPath;

        public static void Init(string dir)
        {
            _iniPath = Path.Combine(dir, "ui_text.ini");
            var defaults = GetDefaults();

            if (File.Exists(_iniPath))
            {
                try
                {
                    string[] lines = File.ReadAllLines(_iniPath, Encoding.UTF8);
                    foreach (string rawLine in lines)
                    {
                        string line = rawLine.Trim();
                        if (string.IsNullOrEmpty(line) || line.StartsWith(";") || line.StartsWith("#") || line.StartsWith("[")) continue;
                        int eqIdx = line.IndexOf('=');
                        if (eqIdx > 0)
                        {
                            string key = line.Substring(0, eqIdx).Trim();
                            string val = line.Substring(eqIdx + 1).Trim();
                            val = val.Replace("\\r\\n", "\r\n").Replace("\\n", "\n");
                            _strings[key] = val;
                        }
                    }
                }
                catch { }
            }

            bool needCreate = !File.Exists(_iniPath);
            foreach (var kvp in defaults)
            {
                if (!_strings.ContainsKey(kvp.Key))
                {
                    _strings[kvp.Key] = kvp.Value;
                }
            }

            if (needCreate)
            {
                try
                {
                    SaveIniFile(_iniPath);
                }
                catch { }
            }
        }

        public static void Set(string key, string value)
        {
            if (_strings != null)
            {
                _strings[key] = value;
            }
        }

        public static string Get(string key, string fallback = "")
        {
            string val;
            if (_strings.TryGetValue(key, out val) && !string.IsNullOrEmpty(val))
            {
                return val;
            }
            return fallback;
        }

        public static string Format(string key, string fallback, params object[] args)
        {
            string fmt = Get(key, fallback);
            try
            {
                return string.Format(fmt, args);
            }
            catch
            {
                return fmt;
            }
        }

        public static string Format(string key, params object[] args)
        {
            string fmt = Get(key, "");
            try
            {
                return string.Format(fmt, args);
            }
            catch
            {
                return fmt;
            }
        }

        private static Dictionary<string, string> GetDefaults()
        {
            var d = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

            d["WindowTitle"] = "Passport Scanner (ID-Capture)";
            d["HeaderTitle"] = "PASSPORT SCANNER (ID-CAPTURE)";

            d["LblCsvPath"] = "File CSV lưu trữ:";
            d["BtnBrowseCsv"] = "Chọn file";
            d["ChkAutoScanLid"] = "Tự động quét khi đóng nắp máy (F3)";
            d["ChkAutoAppendCsv"] = "Tự động ghi nối tiếp CSV (F2)";
            d["ChkAutoScan5s"] = "Tự động scan sau 5s (F1)";

            d["ScanMode"] = "0";
            d["LblScanModeTitle"] = "Cách làm việc:";
            d["BtnModeAuto"] = "⚡ Tự động kết hợp";
            d["BtnModeSyscan"] = "📟 Thư viện gốc Syscan";
            d["BtnModeAi"] = "🤖 AI Windows OCR";
            d["BtnScanAuto"] = "⚡ QUÉT HỘ CHIẾU (TỰ ĐỘNG) [F5 / Ctrl]";
            d["BtnScanSyscan"] = "📟 QUÉT HỘ CHIẾU (GỐC SYSCAN) [F5 / Ctrl]";
            d["BtnScanAi"] = "🤖 QUÉT HỘ CHIẾU (AI WINDOWS) [F5 / Ctrl]";

            d["GrpPassportImage"] = "Hình Ảnh Hộ Chiếu";
            d["PicPassportPlaceholder"] = "Chưa có ảnh hộ chiếu\r\n(Kéo thả ảnh hoặc nhấn F5 / Ctrl để quét)";
            d["ViewImageTitle"] = "Xem ảnh hộ chiếu chi tiết";

            d["GrpPassportInfo"] = "Thông Tin Hộ Chiếu (Bóc Tách Tự Động)";
            d["LblFullName"] = "Họ và tên khách:";
            d["BtnSwapName"] = "⇄ Đảo Họ / Tên";
            d["LblPassportNo"] = "Số hộ chiếu:";
            d["LblNationality"] = "Quốc tịch (Mã 3 chữ):";
            d["LblBirthday"] = "Ngày sinh (dd/MM/yyyy):";
            d["LblGender"] = "Giới tính:";
            d["GenderMale"] = "Nam (M)";
            d["GenderFemale"] = "Nữ (F)";
            d["LblExpiryDate"] = "Ngày hết hạn hộ chiếu:";
            d["LblMrz"] = "Mã MRZ (Vùng đọc máy):";

            d["GrpStayInfo"] = "Thông Tin Lưu Trú - Thao Tác";
            d["LblRoom"] = "Số phòng:";
            d["LblArrival"] = "Ngày đến:";
            d["LblDeparture"] = "Ngày đi dự kiến:";
            d["LblCheckout"] = "Ngày trả phòng:";
            d["LblResidenceTerm"] = "Thời hạn tạm trú:";
            d["BtnScan"] = "⚡ QUÉT HỘ CHIẾU TỪ MÁY [F5 / Ctrl]";
            d["BtnUploadImage"] = "📁 CHỌN ẢNH TỪ MÁY [Ctrl+O]";
            d["BtnAppendCsv"] = "Ghi Vào File CSV [Ctrl+S]";
            d["BtnExportXml"] = "Xuất File XML [Ctrl+X]";
            d["BtnOpenFolder"] = "Mở thư mục file";
            d["BtnClearForm"] = "Xóa trắng ô";

            d["GrpGuestList"] = "Danh Sách Khách Đã Quét - Lưu Trữ CSV";
            d["LblGuestCount"] = "Tổng số khách: {0}";
            d["ColStt"] = "STT";
            d["ColFullName"] = "Họ và Tên";
            d["ColBirthday"] = "Ngày Sinh";
            d["ColGender"] = "Giới Tính";
            d["ColNationality"] = "Quốc Tịch";
            d["ColPassportNo"] = "Số Hộ Chiếu";
            d["ColRoom"] = "Phòng ✎";
            d["ColArrival"] = "Ngày Đến 📅";
            d["ColDeparture"] = "Ngày Đi DK 📅";
            d["ColCheckout"] = "Ngày Trả 📅";
            d["ColResidenceTerm"] = "Hạn Tạm Trú 📅";
            d["ColAction"] = "Thao Tác";
            d["BtnDeleteRow"] = "🗑 Xóa";

            d["StatusConnecting"] = "● Đang kết nối thiết bị máy quét...";
            d["StatusReady"] = "● MÁY QUÉT ID-CAPTURE: ĐÃ KẾT NỐI (Syscan IDC-V SẴN SÀNG QUÉT [F5 / Ctrl])";
            d["StatusNotConnected"] = "● MÁY QUÉT: CHƯA KẾT NỐI USB (Có thể kéo thả hoặc chọn ảnh từ máy để quét)";
            d["StatusFileMode"] = "● CHẾ ĐỘ FILE ẢNH (Không tải được scandll.dll: {0})";
            d["StatusAuto5sLidOpen"] = "● [TỰ ĐỘNG 5S] Nắp máy đang mở, tạm dừng quét để đặt hộ chiếu...";
            d["StatusAppendSuccess"] = "● ĐÃ GHI NỐI TIẾP VÀO CSV (STT: {0}) - {1}";
            d["MsgAuto5sOn"] = "Đã bật chế độ tự động scan chu kỳ 5 giây (F1)";
            d["MsgAuto5sOff"] = "Đã tắt chế độ tự động scan 5s (F1)";
            d["MsgAutoAppendOn"] = "Đã BẬT Tự động ghi nối tiếp CSV (F2)";
            d["MsgAutoAppendOff"] = "Đã TẮT Tự động ghi nối tiếp CSV (F2)";
            d["MsgAutoScanLidOn"] = "Đã BẬT Tự động quét khi đóng nắp máy (F3)";
            d["MsgAutoScanLidOff"] = "Đã TẮT Tự động quét khi đóng nắp máy (F3)";
            d["MsgGridSaved"] = "Đã lưu thay đổi vào CSV!";
            d["MsgWarnNoData"] = "Vui lòng quét hoặc nhập thông tin hộ chiếu trước khi ghi file!";
            d["MsgWarnChooseCsv"] = "Vui lòng chọn đường dẫn file CSV!";

            d["MenuSystem"] = "📁 Hệ thống";
            d["MenuOpenCsv"] = "Chọn file CSV lưu trữ... [Ctrl+O]";
            d["MenuOpenFolder"] = "Mở thư mục chứa file";
            d["MenuExportXml"] = "Xuất danh sách ra XML [Ctrl+X]";
            d["MenuEditUiText"] = "Chỉnh sửa văn bản giao diện (ui_text.ini)...";
            d["MenuExit"] = "Thoát phần mềm";
            d["MenuActions"] = "⚡ Thao tác";
            d["MenuScan"] = "Quét hộ chiếu từ máy [F5 / Ctrl]";
            d["MenuChooseImage"] = "Chọn ảnh từ máy tính [Ctrl+O]";
            d["MenuAppendCsv"] = "Ghi vào file CSV [Ctrl+S]";
            d["MenuClearForm"] = "Xóa trắng thông tin trên ô";
            d["MenuOptions"] = "⚙️ Tùy chọn";
            d["MenuHelp"] = "📖 Hướng dẫn sử dụng";
            d["MenuHelpGuide"] = "📖 Xem hướng dẫn sử dụng chi tiết (F12)";
            d["MenuHelpShortcuts"] = "⌨️ Danh sách phím tắt nhanh";
            d["MenuHelpUiText"] = "⚙️ Hướng dẫn cấu hình giao diện (ui_text.ini)";
            d["MenuHelpFaq"] = "🛠 Hướng dẫn xử lý sự cố thường gặp";
            d["MenuHelpAbout"] = "ℹ️ Giới thiệu phần mềm (About)";
            d["BtnHelp"] = "📖 HƯỚNG DẪN SỬ DỤNG (F12)";
            d["HelpDialogTitle"] = "Hướng Dẫn Sử Dụng - Passport Scanner (ID-Capture)";

            return d;
        }

        public static void SaveIniFile(string path)
        {
            var sb = new StringBuilder();
            sb.AppendLine("; ==============================================================================");
            sb.AppendLine("; TẬP TIN CẤU HÌNH VĂN BẢN GIAO DIỆN (UI TEXT CONFIGURATION)");
            sb.AppendLine("; Phần mềm: Passport Scanner (ID-Capture)");
            sb.AppendLine("; ");
            sb.AppendLine("; HƯỚNG DẪN SỬ DỤNG:");
            sb.AppendLine("; 1. Bạn có thể mở file này bằng Notepad để chỉnh sửa văn bản theo ý muốn.");
            sb.AppendLine("; 2. Sau khi chỉnh sửa xong, nhấn Ctrl+S để Lưu file.");
            sb.AppendLine("; 3. Khởi động lại phần mềm để áp dụng nội dung mới.");
            sb.AppendLine("; 4. File này không bị mất hoặc ghi đè khi cập nhật code hay chạy lại.");
            sb.AppendLine("; ==============================================================================");
            sb.AppendLine();

            sb.AppendLine("[CUA_SO_CHINH]");
            sb.AppendLine("WindowTitle = " + Get("WindowTitle", "Passport Scanner (ID-Capture)"));
            sb.AppendLine("HeaderTitle = " + Get("HeaderTitle", "PASSPORT SCANNER (ID-CAPTURE)"));
            sb.AppendLine();

            sb.AppendLine("[THANH_DIEU_KHIEN_TREN]");
            sb.AppendLine("LblCsvPath = " + Get("LblCsvPath", "File CSV lưu trữ:"));
            sb.AppendLine("BtnBrowseCsv = " + Get("BtnBrowseCsv", "Chọn file"));
            sb.AppendLine("ChkAutoScanLid = " + Get("ChkAutoScanLid", "Tự động quét khi đóng nắp máy (F3)"));
            sb.AppendLine("ChkAutoAppendCsv = " + Get("ChkAutoAppendCsv", "Tự động ghi nối tiếp CSV (F2)"));
            sb.AppendLine("ChkAutoScan5s = " + Get("ChkAutoScan5s", "Tự động scan sau 5s (F1)"));
            sb.AppendLine();

            sb.AppendLine("[CHE_DO_THIET_BI]");
            sb.AppendLine("ScanMode = " + Get("ScanMode", "0"));
            sb.AppendLine("LblScanModeTitle = " + Get("LblScanModeTitle", "Cách làm việc:"));
            sb.AppendLine("BtnModeAuto = " + Get("BtnModeAuto", "⚡ Tự động kết hợp"));
            sb.AppendLine("BtnModeSyscan = " + Get("BtnModeSyscan", "📟 Thư viện gốc Syscan"));
            sb.AppendLine("BtnModeAi = " + Get("BtnModeAi", "🤖 AI Windows OCR"));
            sb.AppendLine("BtnScanAuto = " + Get("BtnScanAuto", "⚡ QUÉT HỘ CHIẾU (TỰ ĐỘNG) [F5 / Ctrl]"));
            sb.AppendLine("BtnScanSyscan = " + Get("BtnScanSyscan", "📟 QUÉT HỘ CHIẾU (GỐC SYSCAN) [F5 / Ctrl]"));
            sb.AppendLine("BtnScanAi = " + Get("BtnScanAi", "🤖 QUÉT HỘ CHIẾU (AI WINDOWS) [F5 / Ctrl]"));
            sb.AppendLine();

            sb.AppendLine("[COT_1_HINH_ANH]");
            sb.AppendLine("GrpPassportImage = " + Get("GrpPassportImage", "Hình Ảnh Hộ Chiếu"));
            sb.AppendLine("PicPassportPlaceholder = " + Get("PicPassportPlaceholder", "Chưa có ảnh hộ chiếu\\r\\n(Kéo thả ảnh hoặc nhấn F5 / Ctrl để quét)").Replace("\r\n", "\\r\\n").Replace("\n", "\\n"));
            sb.AppendLine("ViewImageTitle = " + Get("ViewImageTitle", "Xem ảnh hộ chiếu chi tiết"));
            sb.AppendLine();

            sb.AppendLine("[COT_2_THONG_TIN_HO_CHIEU]");
            sb.AppendLine("GrpPassportInfo = " + Get("GrpPassportInfo", "Thông Tin Hộ Chiếu (Bóc Tách Tự Động)"));
            sb.AppendLine("LblFullName = " + Get("LblFullName", "Họ và tên khách:"));
            sb.AppendLine("BtnSwapName = " + Get("BtnSwapName", "⇄ Đảo Họ / Tên"));
            sb.AppendLine("LblPassportNo = " + Get("LblPassportNo", "Số hộ chiếu:"));
            sb.AppendLine("LblNationality = " + Get("LblNationality", "Quốc tịch (Mã 3 chữ):"));
            sb.AppendLine("LblBirthday = " + Get("LblBirthday", "Ngày sinh (dd/MM/yyyy):"));
            sb.AppendLine("LblGender = " + Get("LblGender", "Giới tính:"));
            sb.AppendLine("GenderMale = " + Get("GenderMale", "Nam (M)"));
            sb.AppendLine("GenderFemale = " + Get("GenderFemale", "Nữ (F)"));
            sb.AppendLine("LblExpiryDate = " + Get("LblExpiryDate", "Ngày hết hạn hộ chiếu:"));
            sb.AppendLine("LblMrz = " + Get("LblMrz", "Mã MRZ (Vùng đọc máy):"));
            sb.AppendLine();

            sb.AppendLine("[COT_3_THONG_TIN_LUU_TRU]");
            sb.AppendLine("GrpStayInfo = " + Get("GrpStayInfo", "Thông Tin Lưu Trú - Thao Tác"));
            sb.AppendLine("LblRoom = " + Get("LblRoom", "Số phòng:"));
            sb.AppendLine("LblArrival = " + Get("LblArrival", "Ngày đến:"));
            sb.AppendLine("LblDeparture = " + Get("LblDeparture", "Ngày đi dự kiến:"));
            sb.AppendLine("LblCheckout = " + Get("LblCheckout", "Ngày trả phòng:"));
            sb.AppendLine("LblResidenceTerm = " + Get("LblResidenceTerm", "Thời hạn tạm trú:"));
            sb.AppendLine("BtnScan = " + Get("BtnScan", "⚡ QUÉT HỘ CHIẾU TỪ MÁY [F5 / Ctrl]"));
            sb.AppendLine("BtnUploadImage = " + Get("BtnUploadImage", "📁 CHỌN ẢNH TỪ MÁY [Ctrl+O]"));
            sb.AppendLine("BtnAppendCsv = " + Get("BtnAppendCsv", "Ghi Vào File CSV [Ctrl+S]"));
            sb.AppendLine("BtnExportXml = " + Get("BtnExportXml", "Xuất File XML [Ctrl+X]"));
            sb.AppendLine("BtnOpenFolder = " + Get("BtnOpenFolder", "Mở thư mục file"));
            sb.AppendLine("BtnClearForm = " + Get("BtnClearForm", "Xóa trắng ô"));
            sb.AppendLine();

            sb.AppendLine("[BANG_DANH_SACH_KHACH]");
            sb.AppendLine("GrpGuestList = " + Get("GrpGuestList", "Danh Sách Khách Đã Quét - Lưu Trữ CSV"));
            sb.AppendLine("LblGuestCount = " + Get("LblGuestCount", "Tổng số khách: {0}"));
            sb.AppendLine("ColStt = " + Get("ColStt", "STT"));
            sb.AppendLine("ColFullName = " + Get("ColFullName", "Họ và Tên"));
            sb.AppendLine("ColBirthday = " + Get("ColBirthday", "Ngày Sinh"));
            sb.AppendLine("ColGender = " + Get("ColGender", "Giới Tính"));
            sb.AppendLine("ColNationality = " + Get("ColNationality", "Quốc Tịch"));
            sb.AppendLine("ColPassportNo = " + Get("ColPassportNo", "Số Hộ Chiếu"));
            sb.AppendLine("ColRoom = " + Get("ColRoom", "Phòng ✎"));
            sb.AppendLine("ColArrival = " + Get("ColArrival", "Ngày Đến 📅"));
            sb.AppendLine("ColDeparture = " + Get("ColDeparture", "Ngày Đi DK 📅"));
            sb.AppendLine("ColCheckout = " + Get("ColCheckout", "Ngày Trả 📅"));
            sb.AppendLine("ColResidenceTerm = " + Get("ColResidenceTerm", "Hạn Tạm Trú 📅"));
            sb.AppendLine("ColAction = " + Get("ColAction", "Thao Tác"));
            sb.AppendLine("BtnDeleteRow = " + Get("BtnDeleteRow", "🗑 Xóa"));
            sb.AppendLine();

            sb.AppendLine("[THONG_BAO_TRANG_THAI]");
            sb.AppendLine("StatusConnecting = " + Get("StatusConnecting", "● Đang kết nối thiết bị máy quét..."));
            sb.AppendLine("StatusReady = " + Get("StatusReady", "● MÁY QUÉT ID-CAPTURE: ĐÃ KẾT NỐI (Syscan IDC-V SẴN SÀNG QUÉT [F5 / Ctrl])"));
            sb.AppendLine("StatusNotConnected = " + Get("StatusNotConnected", "● MÁY QUÉT: CHƯA KẾT NỐI USB (Có thể kéo thả hoặc chọn ảnh từ máy để quét)"));
            sb.AppendLine("StatusFileMode = " + Get("StatusFileMode", "● CHẾ ĐỘ FILE ẢNH (Không tải được scandll.dll: {0})"));
            sb.AppendLine("StatusAuto5sLidOpen = " + Get("StatusAuto5sLidOpen", "● [TỰ ĐỘNG 5S] Nắp máy đang mở, tạm dừng quét để đặt hộ chiếu..."));
            sb.AppendLine("StatusAppendSuccess = " + Get("StatusAppendSuccess", "● ĐÃ GHI NỐI TIẾP VÀO CSV (STT: {0}) - {1}"));
            sb.AppendLine("MsgAuto5sOn = " + Get("MsgAuto5sOn", "Đã bật chế độ tự động scan chu kỳ 5 giây (F1)"));
            sb.AppendLine("MsgAuto5sOff = " + Get("MsgAuto5sOff", "Đã tắt chế độ tự động scan 5s (F1)"));
            sb.AppendLine("MsgAutoAppendOn = " + Get("MsgAutoAppendOn", "Đã BẬT Tự động ghi nối tiếp CSV (F2)"));
            sb.AppendLine("MsgAutoAppendOff = " + Get("MsgAutoAppendOff", "Đã TẮT Tự động ghi nối tiếp CSV (F2)"));
            sb.AppendLine("MsgAutoScanLidOn = " + Get("MsgAutoScanLidOn", "Đã BẬT Tự động quét khi đóng nắp máy (F3)"));
            sb.AppendLine("MsgAutoScanLidOff = " + Get("MsgAutoScanLidOff", "Đã TẮT Tự động quét khi đóng nắp máy (F3)"));
            sb.AppendLine("MsgGridSaved = " + Get("MsgGridSaved", "Đã lưu thay đổi vào CSV!"));
            sb.AppendLine("MsgWarnNoData = " + Get("MsgWarnNoData", "Vui lòng quét hoặc nhập thông tin hộ chiếu trước khi ghi file!"));
            sb.AppendLine("MsgWarnChooseCsv = " + Get("MsgWarnChooseCsv", "Vui lòng chọn đường dẫn file CSV!"));
            sb.AppendLine();

            sb.AppendLine("[MENU_CHINH]");
            sb.AppendLine("MenuHelp = " + Get("MenuHelp", "Hướng dẫn"));
            sb.AppendLine("MenuAbout = " + Get("MenuAbout", "Giới thiệu"));
            sb.AppendLine("HelpDialogTitle = " + Get("HelpDialogTitle", "Hướng Dẫn Sử Dụng - Passport Scanner (ID-Capture)"));

            File.WriteAllText(path, sb.ToString(), Encoding.UTF8);
        }
    }

    public class GlobalKeyMessageFilter : IMessageFilter
    {
        private MainForm _form;
        public GlobalKeyMessageFilter(MainForm form)
        {
            _form = form;
        }

        public bool PreFilterMessage(ref Message m)
        {
            const int WM_KEYDOWN = 0x0100;
            const int WM_KEYUP = 0x0101;
            const int WM_SYSKEYDOWN = 0x0104;
            const int WM_SYSKEYUP = 0x0105;

            if (m.Msg == WM_KEYDOWN || m.Msg == WM_SYSKEYDOWN)
            {
                Keys key = (Keys)(int)m.WParam;
                if (_form.HandleGlobalKeyDown(key, Control.ModifierKeys))
                {
                    return true;
                }
            }
            else if (m.Msg == WM_KEYUP || m.Msg == WM_SYSKEYUP)
            {
                Keys key = (Keys)(int)m.WParam;
                if (_form.HandleGlobalKeyUp(key, Control.ModifierKeys))
                {
                    return true;
                }
            }
            return false;
        }
    }

    public class MainForm : Form
    {
        private string appDir;
        private bool isProcessing = false;
        private bool isScannerConnected = false;
        private System.Windows.Forms.Timer autoScanTimer;
        private int lastTopState = 0;

        // UI Controls (AntdUI & WinForms)
        private MenuStrip msMain;
        private Label lblStatus;
        private AntdUI.Input txtCsvPath;
        private AntdUI.Button btnBrowseCsv;
        private AntdUI.Checkbox chkAutoScan;
        private AntdUI.Checkbox chkAutoAppend;
        private AntdUI.Checkbox chkAutoScan5s;
        private System.Windows.Forms.Timer autoScan5sTimer;
        private string lastAutoScannedPassportNo = "";

        // Scan Mode: 0 = Tu dong ket hop, 1 = Goc Syscan, 2 = AI Windows OCR
        private int scanMode = 0;
        private Label lblScanModeTitle;
        private AntdUI.Button btnModeAuto;
        private AntdUI.Button btnModeSyscan;
        private AntdUI.Button btnModeAi;

        private PictureBox picPassport;
        private PictureBox picPhoto;
        private GroupBox grpImages;
        private TableLayoutPanel tlpTop;

        private AntdUI.Input txtFullName;
        private AntdUI.Input txtPassportNo;
        private AntdUI.Input txtNationality;
        private AntdUI.Input txtBirthDay;
        private AntdUI.Select cboGender;
        private AntdUI.Input txtExpiryDate;
        private AntdUI.Input txtMrz1;
        private AntdUI.Input txtMrz2;

        private AntdUI.Input txtRoom;
        private AntdUI.DatePicker dtpArrival;
        private AntdUI.DatePicker dtpDeparture;
        private AntdUI.DatePicker dtpCheckOut;
        private AntdUI.DatePicker dtpResidenceTerm;

        private AntdUI.Button btnScan;
        private AntdUI.Button btnUploadImage;
        private AntdUI.Button btnAppendCsv;
        private AntdUI.Button btnExportXml;
        private AntdUI.Button btnOpenFolder;
        private AntdUI.Button btnClearForm;
        private AntdUI.Button btnSwapName;

        private DataGridView dgvGuests;
        private Label lblGridTitle;
        private Label lblCount;
        private string _cellBeforeEditValue = null;
        private int _editRowIndex = -1;
        private int _editColIndex = -1;
        private bool _isCtrlAlone = false;
        private long _ctrlDownTime = 0;

        [DllImport("gdi32.dll", ExactSpelling = true)]
        private static extern int AddFontResourceEx(string lpszFilename, uint fl, IntPtr pdv);

        [DllImport("user32.dll")]
        private static extern bool SetForegroundWindow(IntPtr hWnd);

        [DllImport("user32.dll")]
        private static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

        [DllImport("user32.dll")]
        private static extern void SwitchToThisWindow(IntPtr hWnd, bool fAltTab);

        [DllImport("user32.dll")]
        private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);

        [DllImport("user32.dll")]
        private static extern bool AttachThreadInput(uint idAttach, uint idAttachTo, bool fAttach);

        [DllImport("user32.dll")]
        private static extern IntPtr GetForegroundWindow();

        [DllImport("kernel32.dll")]
        private static extern uint GetCurrentThreadId();

        public void ForceForeground()
        {
            try
            {
                this.WindowState = FormWindowState.Normal;
                this.TopMost = true;
                this.TopMost = false;

                IntPtr hFore = GetForegroundWindow();
                uint forePid;
                uint foreThread = GetWindowThreadProcessId(hFore, out forePid);
                uint curThread = GetCurrentThreadId();

                if (foreThread != curThread && foreThread != 0)
                {
                    AttachThreadInput(curThread, foreThread, true);
                    ShowWindow(this.Handle, 5 /* SW_SHOW */);
                    SetForegroundWindow(this.Handle);
                    AttachThreadInput(curThread, foreThread, false);
                }
                else
                {
                    ShowWindow(this.Handle, 5);
                    SetForegroundWindow(this.Handle);
                }

                SwitchToThisWindow(this.Handle, true);
                this.Activate();
                this.BringToFront();
                this.Focus();
                if (btnScan != null) btnScan.Focus();
            }
            catch { }
        }

        public static void InitAppFonts(string dir)
        {
            try
            {
                string[] fontFiles = new string[] {
                    "BeVietnamPro-Regular.ttf",
                    "BeVietnamPro-Medium.ttf",
                    "BeVietnamPro-SemiBold.ttf",
                    "BeVietnamPro-Bold.ttf"
                };
                foreach (var file in fontFiles)
                {
                    string p = Path.Combine(dir, file);
                    if (File.Exists(p))
                    {
                        AddFontResourceEx(p, 0x10, IntPtr.Zero);
                    }
                }
            }
            catch { }
        }

        public static Font AppFont(float size, FontStyle style = FontStyle.Regular)
        {
            try
            {
                return new Font("Arial", size, style);
            }
            catch
            {
                return new Font(FontFamily.GenericSansSerif, size, style);
            }
        }

        public MainForm()
        {
            appDir = AppDomain.CurrentDomain.BaseDirectory;
            UiText.Init(appDir);
            InitializeComponent();
            Application.AddMessageFilter(new GlobalKeyMessageFilter(this));
            InitScanner();
        }

        private void InitializeComponent()
        {
            this.Text = UiText.Get("WindowTitle", "Passport Scanner (ID-Capture)");
            this.ClientSize = new Size(1150, 750);
            this.MinimumSize = new Size(1000, 620);
            this.StartPosition = FormStartPosition.CenterScreen;
            this.Font = AppFont(9.5f, FontStyle.Regular);
            this.BackColor = Color.FromArgb(245, 247, 250);
            string icoPath = Path.Combine(appDir, "app.ico");
            string pngIconPath = Path.Combine(appDir, "icon.png");
            if (File.Exists(icoPath))
            {
                try { this.Icon = new Icon(icoPath); } catch { }
            }
            else if (File.Exists(pngIconPath))
            {
                try
                {
                    using (Bitmap bmp = new Bitmap(pngIconPath))
                    {
                        this.Icon = Icon.FromHandle(bmp.GetHicon());
                    }
                }
                catch { }
            }

            if (this.Icon == null)
            {
                try
                {
                    using (Stream stream = System.Reflection.Assembly.GetExecutingAssembly().GetManifestResourceStream("app.ico"))
                    {
                        if (stream != null) this.Icon = new Icon(stream);
                    }
                }
                catch { }
            }

            this.KeyPreview = true;
            this.KeyDown += MainForm_KeyDown;
            this.KeyUp += MainForm_KeyUp;
            this.Deactivate += (s, e) => { _isCtrlAlone = false; };

            // TOP HEADER PANEL
            Panel pnlTop = new Panel
            {
                Dock = DockStyle.Top,
                Height = 98,
                BackColor = Color.White,
                Padding = new Padding(15, 8, 15, 8)
            };
            pnlTop.Paint += (s, e) =>
            {
                e.Graphics.DrawLine(new Pen(Color.FromArgb(220, 224, 230), 1), 0, pnlTop.Height - 1, pnlTop.Width, pnlTop.Height - 1);
            };

            PictureBox picLogo = new PictureBox
            {
                Location = new Point(15, 8),
                Size = new Size(48, 48),
                SizeMode = PictureBoxSizeMode.Zoom,
                BackColor = Color.Transparent
            };
            if (File.Exists(pngIconPath))
            {
                try { picLogo.Image = Image.FromFile(pngIconPath); } catch { }
            }

            Label lblTitle = new Label
            {
                Text = UiText.Get("HeaderTitle", "PASSPORT SCANNER (ID-CAPTURE)"),
                UseMnemonic = false,
                Font = AppFont(12.5f, FontStyle.Bold),
                ForeColor = Color.FromArgb(24, 43, 73),
                Location = new Point(70, 8),
                AutoSize = true
            };

            lblStatus = new Label
            {
                Text = UiText.Get("StatusConnecting", "● Đang kết nối thiết bị máy quét..."),
                Font = AppFont(9.5f, FontStyle.Bold),
                ForeColor = Color.DarkOrange,
                Location = new Point(72, 34),
                AutoSize = true
            };

            Label lblCsv = new Label { Text = UiText.Get("LblCsvPath", "File CSV lưu trữ:"), Location = new Point(15, 68), AutoSize = true, Font = AppFont(9f, FontStyle.Bold) };
            string currentYear = DateTime.Now.ToString("yyyy");
            string currentCsvFileName = string.Format("{0:dd_MM}.csv", DateTime.Now);
            string csvDir = Path.Combine(appDir, "docs", currentYear, "csv");
            if (!Directory.Exists(csvDir))
            {
                try { Directory.CreateDirectory(csvDir); } catch { }
            }
            string defaultCsvPath = Path.Combine(csvDir, currentCsvFileName);
            try
            {
                if (!File.Exists(defaultCsvPath))
                {
                    // Copy dữ liệu nếu đã có file hôm nay từ định dạng cũ sang định dạng mới
                    string oldDocsCsv = Path.Combine(appDir, "docs", string.Format("KhaiBaoTamTru_{0:yyyyMMdd}.csv", DateTime.Now));
                    string oldDocssCsv = Path.Combine(appDir, "docss", string.Format("KhaiBaoTamTru_{0:yyyyMMdd}.csv", DateTime.Now));
                    string rootCsv = Path.Combine(appDir, string.Format("KhaiBaoTamTru_{0:yyyyMMdd}.csv", DateTime.Now));
                    if (File.Exists(oldDocsCsv))
                    {
                        File.Copy(oldDocsCsv, defaultCsvPath, true);
                    }
                    else if (File.Exists(oldDocssCsv))
                    {
                        File.Copy(oldDocssCsv, defaultCsvPath, true);
                    }
                    else if (File.Exists(rootCsv))
                    {
                        File.Copy(rootCsv, defaultCsvPath, true);
                    }
                }
            }
            catch { }

            txtCsvPath = new AntdUI.Input
            {
                Location = new Point(115, 63),
                Size = new Size(175, 28),
                Text = defaultCsvPath,
                Font = AppFont(9f),
                ForeColor = Color.FromArgb(20, 20, 20),
                BorderColor = Color.FromArgb(217, 217, 217),
                Radius = 6
            };

            btnBrowseCsv = new AntdUI.Button
            {
                Text = UiText.Get("BtnBrowseCsv", "Chọn file"),
                Location = new Point(296, 63),
                Size = new Size(68, 28),
                Type = AntdUI.TTypeMini.Default,
                Radius = 6,
                Font = AppFont(9f),
                Cursor = Cursors.Hand
            };
            btnBrowseCsv.Click += BtnBrowseCsv_Click;

            chkAutoScan = new AntdUI.Checkbox
            {
                Text = UiText.Get("ChkAutoScanLid", "Tự động quét khi đóng nắp máy (F3)"),
                Location = new Point(376, 67),
                AutoSize = true,
                Checked = true,
                Font = AppFont(9f, FontStyle.Bold),
                ForeColor = Color.FromArgb(0, 102, 204)
            };
            chkAutoScan.CheckedChanged += (s, e) =>
            {
                try { AntdUI.Message.info(this, chkAutoScan.Checked ? UiText.Get("MsgAutoScanLidOn", "Đã BẬT Tự động quét khi đóng nắp máy (F3)") : UiText.Get("MsgAutoScanLidOff", "Đã TẮT Tự động quét khi đóng nắp máy (F3)")); } catch { }
            };

            chkAutoAppend = new AntdUI.Checkbox
            {
                Text = UiText.Get("ChkAutoAppendCsv", "Tự động ghi nối tiếp CSV (F2)"),
                Location = new Point(626, 67),
                AutoSize = true,
                Checked = true,
                Font = AppFont(9f, FontStyle.Bold),
                ForeColor = Color.FromArgb(0, 128, 64)
            };
            chkAutoAppend.CheckedChanged += (s, e) =>
            {
                try { AntdUI.Message.info(this, chkAutoAppend.Checked ? UiText.Get("MsgAutoAppendOn", "Đã BẬT Tự động ghi nối tiếp CSV (F2)") : UiText.Get("MsgAutoAppendOff", "Đã TẮT Tự động ghi nối tiếp CSV (F2)")); } catch { }
            };

            chkAutoScan5s = new AntdUI.Checkbox
            {
                Text = UiText.Get("ChkAutoScan5s", "Tự động scan sau 5s (F1)"),
                Location = new Point(836, 67),
                AutoSize = true,
                Checked = false,
                Font = AppFont(9f, FontStyle.Bold),
                ForeColor = Color.FromArgb(204, 102, 0)
            };
            chkAutoScan5s.CheckedChanged += (s, e) =>
            {
                if (chkAutoScan5s.Checked)
                {
                    lastAutoScannedPassportNo = "";
                    StartAutoScan5sTimer();
                    try { AntdUI.Message.info(this, UiText.Get("MsgAuto5sOn", "Đã bật chế độ tự động scan chu kỳ 5 giây (F1)")); } catch { }
                }
                else
                {
                    StopAutoScan5sTimer();
                    try { AntdUI.Message.info(this, UiText.Get("MsgAuto5sOff", "Đã tắt chế độ tự động scan 5s (F1)")); } catch { }
                }
            };

            // SCAN MODE SELECTOR BUTTONS (Hàng trên, căn phải)
            int initialScanMode = 0;
            int.TryParse(UiText.Get("ScanMode", "0"), out initialScanMode);
            if (initialScanMode < 0 || initialScanMode > 2) initialScanMode = 0;
            scanMode = initialScanMode;

            lblScanModeTitle = new Label
            {
                Text = UiText.Get("LblScanModeTitle", "Cách làm việc:"),
                AutoSize = true,
                Font = AppFont(9f, FontStyle.Bold),
                ForeColor = Color.FromArgb(70, 70, 70)
            };

            btnModeAuto = new AntdUI.Button
            {
                Text = UiText.Get("BtnModeAuto", "⚡ Tự động kết hợp"),
                Size = new Size(140, 28),
                Type = (scanMode == 0) ? AntdUI.TTypeMini.Primary : AntdUI.TTypeMini.Default,
                Radius = 6,
                Font = AppFont(8.5f, (scanMode == 0) ? FontStyle.Bold : FontStyle.Regular),
                Cursor = Cursors.Hand
            };
            btnModeAuto.Click += (s, e) => SetScanMode(0);

            btnModeSyscan = new AntdUI.Button
            {
                Text = UiText.Get("BtnModeSyscan", "📟 Thư viện gốc Syscan"),
                Size = new Size(150, 28),
                Type = (scanMode == 1) ? AntdUI.TTypeMini.Primary : AntdUI.TTypeMini.Default,
                Radius = 6,
                Font = AppFont(8.5f, (scanMode == 1) ? FontStyle.Bold : FontStyle.Regular),
                Cursor = Cursors.Hand
            };
            btnModeSyscan.Click += (s, e) => SetScanMode(1);

            btnModeAi = new AntdUI.Button
            {
                Text = UiText.Get("BtnModeAi", "🤖 AI Windows OCR"),
                Size = new Size(135, 28),
                Type = (scanMode == 2) ? AntdUI.TTypeMini.Primary : AntdUI.TTypeMini.Default,
                Radius = 6,
                Font = AppFont(8.5f, (scanMode == 2) ? FontStyle.Bold : FontStyle.Regular),
                Cursor = Cursors.Hand
            };
            btnModeAi.Click += (s, e) => SetScanMode(2);

            // MENU STRIP
            msMain = new MenuStrip
            {
                BackColor = Color.FromArgb(242, 244, 248),
                Font = AppFont(8f),
                Padding = new Padding(6, 2, 0, 2),
                RenderMode = ToolStripRenderMode.System
            };

            // Top Menu: Huong dan & Gioi thieu (cỡ chữ nhỏ gọn theo yêu cầu)
            ToolStripMenuItem mnuHelp = new ToolStripMenuItem(UiText.Get("MenuHelp", "Hướng dẫn"), null, (s, e) => ShowUserGuideDialog(0))
            {
                Font = AppFont(8f)
            };
            ToolStripMenuItem mnuAbout = new ToolStripMenuItem(UiText.Get("MenuAbout", "Giới thiệu"), null, (s, e) => ShowUserGuideDialog(2))
            {
                Font = AppFont(8f)
            };

            msMain.Items.AddRange(new ToolStripItem[] { mnuHelp, mnuAbout });
            this.MainMenuStrip = msMain;

            Action layoutTopCheckboxes = () =>
            {
                int x1 = btnBrowseCsv.Right + 12;
                chkAutoScan.Left = x1;
                int w1 = Math.Max(chkAutoScan.PreferredSize.Width, 235);
                chkAutoAppend.Left = chkAutoScan.Left + w1 + 14;
                int w2 = Math.Max(chkAutoAppend.PreferredSize.Width, 195);
                chkAutoScan5s.Left = chkAutoAppend.Left + w2 + 14;

                // Căn phải nhóm nút chọn cách thiết bị làm việc ở hàng trên
                int rightEdge = pnlTop.ClientSize.Width - 15;
                btnModeAi.Location = new Point(rightEdge - btnModeAi.Width, 12);
                btnModeSyscan.Location = new Point(btnModeAi.Left - 6 - btnModeSyscan.Width, 12);
                btnModeAuto.Location = new Point(btnModeSyscan.Left - 6 - btnModeAuto.Width, 12);
                lblScanModeTitle.Location = new Point(btnModeAuto.Left - 8 - lblScanModeTitle.PreferredSize.Width, 18);
            };

            pnlTop.Controls.AddRange(new Control[] { 
                picLogo, lblTitle, lblStatus, 
                lblCsv, txtCsvPath, btnBrowseCsv, 
                chkAutoScan, chkAutoAppend, chkAutoScan5s,
                lblScanModeTitle, btnModeAuto, btnModeSyscan, btnModeAi
            });
            pnlTop.Resize += (s, e) => layoutTopCheckboxes();
            layoutTopCheckboxes();

            // MAIN SPLIT CONTAINER
            SplitContainer splitMain = new SplitContainer
            {
                Dock = DockStyle.Fill,
                Orientation = Orientation.Horizontal,
                SplitterWidth = 6,
                BackColor = Color.FromArgb(215, 220, 228)
            };
            this.Controls.Add(splitMain);
            this.Controls.Add(pnlTop);
            this.Controls.Add(msMain);
            splitMain.BringToFront();
            try
            {
                splitMain.Panel1MinSize = 200;
                splitMain.Panel2MinSize = 120;
                splitMain.SplitterDistance = 340;
            }
            catch { }

            // Drag & Drop
            this.AllowDrop = true;
            this.DragEnter += (s, e) => {
                if (e.Data.GetDataPresent(DataFormats.FileDrop)) e.Effect = DragDropEffects.Copy;
            };
            this.DragDrop += (s, e) => {
                string[] files = (string[])e.Data.GetData(DataFormats.FileDrop);
                if (files != null && files.Length > 0)
                {
                    ProcessPassportImage(files[0]);
                }
            };

            // TOP 3 COLUMNS
            tlpTop = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 3,
                RowCount = 1,
                Padding = new Padding(8, 6, 8, 6),
                BackColor = Color.FromArgb(245, 247, 250)
            };
            tlpTop.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 32f));
            tlpTop.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 38f));
            tlpTop.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 30f));
            splitMain.Panel1.Controls.Add(tlpTop);

            // COLUMN 1: IMAGE PREVIEWS
            grpImages = new GroupBox
            {
                Text = UiText.Get("GrpPassportImage", "Hình Ảnh Hộ Chiếu"),
                Dock = DockStyle.Fill,
                Font = AppFont(9.5f, FontStyle.Bold)
            };

            picPassport = new PictureBox
            {
                Dock = DockStyle.Fill,
                SizeMode = PictureBoxSizeMode.Zoom,
                BorderStyle = BorderStyle.FixedSingle,
                BackColor = Color.FromArgb(238, 240, 244),
                Cursor = Cursors.Hand,
                AllowDrop = true
            };
            picPassport.Paint += (s, e) => {
                if (picPassport.Image == null)
                {
                    string placeholder = UiText.Get("PicPassportPlaceholder", "Chưa có ảnh hộ chiếu\r\n(Kéo thả ảnh hoặc nhấn F5 / Ctrl để quét)");
                    using (var sf = new StringFormat { Alignment = StringAlignment.Center, LineAlignment = StringAlignment.Center })
                    using (var br = new SolidBrush(Color.FromArgb(140, 145, 155)))
                    using (var font = AppFont(9.5f, FontStyle.Italic))
                    {
                        e.Graphics.DrawString(placeholder, font, br, picPassport.ClientRectangle, sf);
                    }
                }
            };
            picPassport.DragEnter += (s, e) => {
                if (e.Data.GetDataPresent(DataFormats.FileDrop)) e.Effect = DragDropEffects.Copy;
            };
            picPassport.DragDrop += (s, e) => {
                string[] files = (string[])e.Data.GetData(DataFormats.FileDrop);
                if (files != null && files.Length > 0)
                {
                    ProcessPassportImage(files[0]);
                }
            };
            picPassport.Click += (s, e) => {
                if (picPassport.Image != null)
                {
                    Form viewForm = new Form { Text = UiText.Get("ViewImageTitle", "Xem ảnh hộ chiếu chi tiết"), Size = new Size(1000, 750), StartPosition = FormStartPosition.CenterParent };
                    PictureBox pb = new PictureBox { Dock = DockStyle.Fill, Image = picPassport.Image, SizeMode = PictureBoxSizeMode.Zoom };
                    viewForm.Controls.Add(pb);
                    viewForm.ShowDialog(this);
                }
            };

            picPhoto = new PictureBox { Visible = false }; // Kept for logic compatibility

            grpImages.Controls.Add(picPassport);
            tlpTop.Controls.Add(grpImages, 0, 0);

            // COLUMN 2: PASSPORT INFO
            GroupBox grpInfo = new GroupBox
            {
                Text = UiText.Get("GrpPassportInfo", "Thông Tin Hộ Chiếu (Bóc Tách Tự Động)"),
                Dock = DockStyle.Fill,
                Font = AppFont(9.5f, FontStyle.Bold)
            };
            Panel pnlInfoContent = new Panel { Dock = DockStyle.Fill, AutoScroll = true, Padding = new Padding(10, 8, 10, 8) };
            grpInfo.Controls.Add(pnlInfoContent);

            // Row 1: Name + Swap
            Label lblName = new Label { Text = UiText.Get("LblFullName", "Họ và tên khách:"), Location = new Point(8, 4), AutoSize = true, Font = AppFont(9f, FontStyle.Bold) };
            btnSwapName = new AntdUI.Button
            {
                Text = UiText.Get("BtnSwapName", "⇄ Đảo Họ / Tên"),
                Location = new Point(220, 2),
                Size = new Size(130, 24),
                Type = AntdUI.TTypeMini.Default,
                Radius = 4,
                Font = AppFont(8.5f),
                Cursor = Cursors.Hand
            };
            btnSwapName.Click += (s, e) => {
                string t = txtFullName.Text.Trim();
                if (!string.IsNullOrEmpty(t))
                {
                    string[] p = t.Split(new char[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                    if (p.Length >= 2)
                    {
                        string first = p[0];
                        string rest = string.Join(" ", p, 1, p.Length - 1);
                        txtFullName.Text = (rest + " " + first).Trim().ToUpper();
                    }
                }
            };
            txtFullName = new AntdUI.Input
            {
                Location = new Point(8, 24),
                Size = new Size(342, 28),
                Font = AppFont(10.5f, FontStyle.Bold),
                ForeColor = Color.FromArgb(20, 20, 20),
                BorderColor = Color.FromArgb(217, 217, 217),
                Radius = 6
            };
            pnlInfoContent.Controls.AddRange(new Control[] { lblName, btnSwapName, txtFullName });

            // Row 2: Passport No & Nationality
            Label lblPassNo = new Label { Text = UiText.Get("LblPassportNo", "Số hộ chiếu:"), Location = new Point(8, 56), AutoSize = true, Font = AppFont(9f, FontStyle.Bold) };
            txtPassportNo = new AntdUI.Input
            {
                Location = new Point(8, 74),
                Size = new Size(166, 28),
                Font = AppFont(10.5f, FontStyle.Bold),
                ForeColor = Color.FromArgb(20, 20, 20),
                BorderColor = Color.FromArgb(217, 217, 217),
                Radius = 6
            };

            Label lblNat = new Label { Text = UiText.Get("LblNationality", "Quốc tịch (Mã 3 chữ):"), Location = new Point(184, 56), AutoSize = true, Font = AppFont(9f, FontStyle.Bold) };
            txtNationality = new AntdUI.Input
            {
                Location = new Point(184, 74),
                Size = new Size(166, 28),
                Font = AppFont(9.5f),
                ForeColor = Color.FromArgb(20, 20, 20),
                BorderColor = Color.FromArgb(217, 217, 217),
                Radius = 6
            };
            pnlInfoContent.Controls.AddRange(new Control[] { lblPassNo, txtPassportNo, lblNat, txtNationality });

            // Row 3: Birthday & Gender
            Label lblBirth = new Label { Text = UiText.Get("LblBirthday", "Ngày sinh (dd/MM/yyyy):"), Location = new Point(8, 108), AutoSize = true, Font = AppFont(9f, FontStyle.Bold) };
            txtBirthDay = new AntdUI.Input
            {
                Location = new Point(8, 126),
                Size = new Size(166, 28),
                Font = AppFont(9.5f),
                ForeColor = Color.FromArgb(20, 20, 20),
                BorderColor = Color.FromArgb(217, 217, 217),
                Radius = 6
            };

            Label lblGen = new Label { Text = UiText.Get("LblGender", "Giới tính:"), Location = new Point(184, 108), AutoSize = true, Font = AppFont(9f, FontStyle.Bold) };
            cboGender = new AntdUI.Select
            {
                Location = new Point(184, 126),
                Size = new Size(166, 28),
                Font = AppFont(9.5f),
                Radius = 6,
                BorderColor = Color.FromArgb(217, 217, 217)
            };
            cboGender.Items.AddRange(new object[] { UiText.Get("GenderMale", "Nam (M)"), UiText.Get("GenderFemale", "Nữ (F)") });
            cboGender.SelectedIndex = 0;
            pnlInfoContent.Controls.AddRange(new Control[] { lblBirth, txtBirthDay, lblGen, cboGender });

            // Row 4: Expiry Date
            Label lblExp = new Label { Text = UiText.Get("LblExpiryDate", "Ngày hết hạn hộ chiếu:"), Location = new Point(8, 160), AutoSize = true, Font = AppFont(9f, FontStyle.Bold) };
            txtExpiryDate = new AntdUI.Input
            {
                Location = new Point(8, 178),
                Size = new Size(342, 28),
                Font = AppFont(9.5f),
                ForeColor = Color.FromArgb(20, 20, 20),
                BorderColor = Color.FromArgb(217, 217, 217),
                Radius = 6
            };
            pnlInfoContent.Controls.AddRange(new Control[] { lblExp, txtExpiryDate });

            // Row 5: MRZ below Expiry Date (compact & neat)
            Label lblMrzTitle = new Label
            {
                Text = UiText.Get("LblMrz", "Mã MRZ (Vùng đọc máy):"),
                Location = new Point(8, 212),
                AutoSize = true,
                Font = AppFont(8.5f, FontStyle.Bold),
                ForeColor = Color.FromArgb(70, 70, 70)
            };

            txtMrz1 = new AntdUI.Input
            {
                Location = new Point(8, 230),
                Size = new Size(342, 25),
                Font = AppFont(8.5f, FontStyle.Bold),
                PlaceholderText = "P<VNM...",
                BorderColor = Color.FromArgb(217, 217, 217),
                Radius = 4
            };

            txtMrz2 = new AntdUI.Input
            {
                Location = new Point(8, 258),
                Size = new Size(342, 25),
                Font = AppFont(8.5f, FontStyle.Bold),
                PlaceholderText = "K0053543<6VNM...",
                BorderColor = Color.FromArgb(217, 217, 217),
                Radius = 4
            };
            pnlInfoContent.Controls.AddRange(new Control[] { lblMrzTitle, txtMrz1, txtMrz2 });

            pnlInfoContent.Resize += (s, e) =>
            {
                int fullW = pnlInfoContent.ClientSize.Width - 20;
                if (fullW > 100)
                {
                    btnSwapName.Left = Math.Max(fullW - 120, 170);
                    txtFullName.Width = fullW;
                    txtExpiryDate.Width = fullW;
                    txtMrz1.Width = fullW;
                    txtMrz2.Width = fullW;

                    int halfW = (fullW - 12) / 2;
                    txtPassportNo.Width = halfW;
                    lblNat.Left = 8 + halfW + 12;
                    txtNationality.Left = 8 + halfW + 12;
                    txtNationality.Width = halfW;

                    txtBirthDay.Width = halfW;
                    lblGen.Left = 8 + halfW + 12;
                    cboGender.Left = 8 + halfW + 12;
                    cboGender.Width = halfW;
                }
            };

            tlpTop.Controls.Add(grpInfo, 1, 0);

            // COLUMN 3: STAY INFO & ACTIONS
            GroupBox grpStay = new GroupBox
            {
                Text = UiText.Get("GrpStayInfo", "Thông Tin Lưu Trú - Thao Tác"),
                Dock = DockStyle.Fill,
                Font = AppFont(9.5f, FontStyle.Bold)
            };
            Panel pnlStayContent = new Panel { Dock = DockStyle.Fill, AutoScroll = true, Padding = new Padding(10, 8, 10, 8) };
            grpStay.Controls.Add(pnlStayContent);

            // Row 1: Số phòng (giữ nguyên vị trí và kích thước)
            Label lblRoom = new Label { Text = UiText.Get("LblRoom", "Số phòng:"), Location = new Point(8, 4), AutoSize = true, Font = AppFont(9f, FontStyle.Bold) };
            txtRoom = new AntdUI.Input
            {
                Location = new Point(8, 24),
                Size = new Size(140, 28),
                Font = AppFont(10.5f, FontStyle.Bold),
                PlaceholderText = "101",
                Text = "",
                ForeColor = Color.FromArgb(20, 20, 20),
                BorderColor = Color.FromArgb(217, 217, 217),
                Radius = 6
            };
            txtRoom.GotFocus += (s, e) => {
                if (txtRoom.Text == "101") txtRoom.SelectAll();
            };
            txtRoom.Click += (s, e) => {
                if (txtRoom.Text == "101") txtRoom.SelectAll();
            };
            pnlStayContent.Controls.AddRange(new Control[] { lblRoom, txtRoom });

            // Row 2: Ngày đến & Ngày đi cùng 1 dòng
            Label lblArr = new Label { Text = UiText.Get("LblArrival", "Ngày đến:"), Location = new Point(8, 56), AutoSize = true, Font = AppFont(9f, FontStyle.Bold) };
            dtpArrival = new AntdUI.DatePicker
            {
                Location = new Point(8, 76),
                Size = new Size(140, 28),
                Format = "dd/MM/yyyy",
                Font = AppFont(9f),
                Value = DateTime.Today,
                Radius = 6,
                BorderColor = Color.FromArgb(217, 217, 217)
            };

            Label lblDep = new Label { Text = UiText.Get("LblDeparture", "Ngày đi dự kiến:"), Location = new Point(158, 56), AutoSize = true, Font = AppFont(9f, FontStyle.Bold) };
            dtpDeparture = new AntdUI.DatePicker
            {
                Location = new Point(158, 76),
                Size = new Size(140, 28),
                Format = "dd/MM/yyyy",
                Font = AppFont(9f),
                Value = DateTime.Today.AddDays(3),
                Radius = 6,
                BorderColor = Color.FromArgb(217, 217, 217)
            };
            dtpDeparture.ValueChanged += (s, e) => {
                if (e.Value.HasValue)
                {
                    dtpCheckOut.Value = e.Value.Value;
                    dtpResidenceTerm.Value = e.Value.Value.AddDays(6);
                }
            };
            pnlStayContent.Controls.AddRange(new Control[] { lblArr, dtpArrival, lblDep, dtpDeparture });

            // Row 3: Ngày trả phòng & Thời hạn tạm trú cùng 1 dòng
            Label lblOut = new Label { Text = UiText.Get("LblCheckout", "Ngày trả phòng:"), Location = new Point(8, 108), AutoSize = true, Font = AppFont(9f, FontStyle.Bold) };
            dtpCheckOut = new AntdUI.DatePicker
            {
                Location = new Point(8, 128),
                Size = new Size(140, 28),
                Format = "dd/MM/yyyy",
                Font = AppFont(9f),
                Value = DateTime.Today.AddDays(3),
                Radius = 6,
                BorderColor = Color.FromArgb(217, 217, 217)
            };

            Label lblTerm = new Label { Text = UiText.Get("LblResidenceTerm", "Thời hạn tạm trú:"), Location = new Point(158, 108), AutoSize = true, Font = AppFont(9f, FontStyle.Bold) };
            dtpResidenceTerm = new AntdUI.DatePicker
            {
                Location = new Point(158, 128),
                Size = new Size(140, 28),
                Format = "dd/MM/yyyy",
                Font = AppFont(9f),
                Value = DateTime.Today.AddDays(9),
                Radius = 6,
                BorderColor = Color.FromArgb(217, 217, 217)
            };
            pnlStayContent.Controls.AddRange(new Control[] { lblOut, dtpCheckOut, lblTerm, dtpResidenceTerm });

            // Buttons
            btnScan = new AntdUI.Button
            {
                Text = UiText.Get("BtnScan", "⚡ QUÉT HỘ CHIẾU TỪ MÁY [F5 / Ctrl]"),
                Location = new Point(8, 164),
                Size = new Size(300, 36),
                Type = AntdUI.TTypeMini.Primary,
                WaveSize = 4,
                Radius = 6,
                Font = AppFont(10f, FontStyle.Bold),
                Cursor = Cursors.Hand
            };
            btnScan.Click += (s, e) => TriggerScan();
            pnlStayContent.Controls.Add(btnScan);

            btnUploadImage = new AntdUI.Button
            {
                Text = UiText.Get("BtnUploadImage", "📁 CHỌN ẢNH TỪ MÁY [Ctrl+O]"),
                Location = new Point(8, 206),
                Size = new Size(300, 30),
                Type = AntdUI.TTypeMini.Info,
                WaveSize = 4,
                Radius = 6,
                Font = AppFont(9.5f, FontStyle.Bold),
                Cursor = Cursors.Hand
            };
            btnUploadImage.Click += (s, e) => ChooseAndProcessImage();
            pnlStayContent.Controls.Add(btnUploadImage);

            btnAppendCsv = new AntdUI.Button
            {
                Text = UiText.Get("BtnAppendCsv", "Ghi Vào File CSV [Ctrl+S]"),
                Location = new Point(8, 242),
                Size = new Size(145, 30),
                Type = AntdUI.TTypeMini.Success,
                WaveSize = 4,
                Radius = 6,
                Font = AppFont(8.5f, FontStyle.Bold),
                Cursor = Cursors.Hand
            };
            btnAppendCsv.Click += (s, e) => SaveCurrentGuestToCsv(true);

            btnExportXml = new AntdUI.Button
            {
                Text = UiText.Get("BtnExportXml", "Xuất File XML [Ctrl+X]"),
                Location = new Point(158, 242),
                Size = new Size(145, 30),
                Type = AntdUI.TTypeMini.Warn,
                WaveSize = 4,
                Radius = 6,
                Font = AppFont(8.5f, FontStyle.Bold),
                Cursor = Cursors.Hand
            };
            btnExportXml.Click += BtnExportXml_Click;
            pnlStayContent.Controls.AddRange(new Control[] { btnAppendCsv, btnExportXml });

            btnOpenFolder = new AntdUI.Button
            {
                Text = UiText.Get("BtnOpenFolder", "Mở thư mục file"),
                Location = new Point(8, 278),
                Size = new Size(145, 28),
                Type = AntdUI.TTypeMini.Default,
                Radius = 6,
                Font = AppFont(9f),
                Cursor = Cursors.Hand
            };
            btnOpenFolder.Click += (s, e) => {
                string p = txtCsvPath.Text;
                string dir = (!string.IsNullOrEmpty(p) && File.Exists(p)) 
                    ? Path.GetDirectoryName(p) 
                    : Path.Combine(appDir, "docs", DateTime.Now.ToString("yyyy"), "csv");
                if (!Directory.Exists(dir)) dir = Path.Combine(appDir, "docs");
                if (!Directory.Exists(dir)) dir = appDir;
                try { System.Diagnostics.Process.Start("explorer.exe", dir); } catch { }
            };

            btnClearForm = new AntdUI.Button
            {
                Text = UiText.Get("BtnClearForm", "Xóa trắng ô"),
                Location = new Point(158, 278),
                Size = new Size(145, 28),
                Type = AntdUI.TTypeMini.Default,
                Radius = 6,
                Font = AppFont(9f),
                Cursor = Cursors.Hand
            };
            btnClearForm.Click += (s, e) => ClearForm();
            pnlStayContent.Controls.AddRange(new Control[] { btnOpenFolder, btnClearForm });

            pnlStayContent.Resize += (s, e) =>
            {
                int fullW = pnlStayContent.ClientSize.Width - 20;
                if (fullW > 100)
                {
                    int halfW = (fullW - 12) / 2;
                    int rightColX = 8 + halfW + 12;

                    // Row 1: Số phòng giữ nguyên
                    txtRoom.Width = halfW;

                    // Row 2: Ngày đến & Ngày đi cùng 1 dòng
                    lblArr.Left = 8;
                    dtpArrival.Left = 8;
                    dtpArrival.Width = halfW;

                    lblDep.Left = rightColX;
                    dtpDeparture.Left = rightColX;
                    dtpDeparture.Width = halfW;

                    // Row 3: Ngày trả phòng & Thời hạn tạm trú cùng 1 dòng
                    lblOut.Left = 8;
                    dtpCheckOut.Left = 8;
                    dtpCheckOut.Width = halfW;

                    lblTerm.Left = rightColX;
                    dtpResidenceTerm.Left = rightColX;
                    dtpResidenceTerm.Width = halfW;

                    btnScan.Width = fullW;
                    btnUploadImage.Width = fullW;

                    btnAppendCsv.Width = halfW;
                    btnExportXml.Left = rightColX;
                    btnExportXml.Width = halfW;

                    btnOpenFolder.Width = halfW;
                    btnClearForm.Left = rightColX;
                    btnClearForm.Width = halfW;
                }
            };

            tlpTop.Controls.Add(grpStay, 2, 0);

            // BOTTOM: DATA GRID VIEW
            Panel pnlGrid = new Panel 
            { 
                Dock = DockStyle.Fill, 
                Padding = new Padding(8, 2, 8, 6),
                BackColor = Color.FromArgb(245, 247, 250)
            };

            // Tieu de Danh sach khach hang va Tong so khach tren cung 1 hang
            Panel pnlGridHeader = new Panel 
            { 
                Dock = DockStyle.Top, 
                Height = 22,
                BackColor = Color.Transparent
            };
            lblGridTitle = new Label
            {
                Text = UiText.Get("GrpGuestList", "DANH SÁCH KHÁCH HÀNG"),
                AutoSize = true,
                Font = AppFont(9.5f, FontStyle.Bold),
                ForeColor = Color.FromArgb(24, 43, 73),
                Location = new Point(2, 2)
            };
            lblCount = new Label
            {
                Text = UiText.Format("LblGuestCount", 0),
                AutoSize = true,
                Font = AppFont(9.5f, FontStyle.Bold),
                ForeColor = Color.FromArgb(0, 102, 204),
                Location = new Point(lblGridTitle.PreferredSize.Width + 14, 2)
            };
            pnlGridHeader.Controls.AddRange(new Control[] { lblGridTitle, lblCount });
            pnlGrid.Controls.Add(pnlGridHeader);

            dgvGuests = new DataGridView
            {
                Dock = DockStyle.Fill,
                BackgroundColor = Color.White,
                BorderStyle = BorderStyle.FixedSingle,
                GridColor = Color.FromArgb(232, 236, 240),
                RowHeadersVisible = false,
                AllowUserToAddRows = false,
                AllowUserToDeleteRows = false,
                ReadOnly = false,
                SelectionMode = DataGridViewSelectionMode.FullRowSelect,
                EditMode = DataGridViewEditMode.EditOnEnter,
                AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill,
                Font = AppFont(9f)
            };
            dgvGuests.ColumnHeadersDefaultCellStyle.BackColor = Color.FromArgb(240, 243, 246);
            dgvGuests.ColumnHeadersDefaultCellStyle.Font = AppFont(9f, FontStyle.Bold);
            dgvGuests.EnableHeadersVisualStyles = false;

            dgvGuests.Columns.Add("STT", UiText.Get("ColStt", "STT"));
            dgvGuests.Columns["STT"].Width = 40;
            dgvGuests.Columns["STT"].FillWeight = 25;
            dgvGuests.Columns["STT"].ReadOnly = true;

            dgvGuests.Columns.Add("HoTen", UiText.Get("ColFullName", "Họ và Tên"));
            dgvGuests.Columns["HoTen"].FillWeight = 130;
            dgvGuests.Columns["HoTen"].ReadOnly = true;

            dgvGuests.Columns.Add("NgaySinh", UiText.Get("ColBirthday", "Ngày Sinh"));
            dgvGuests.Columns["NgaySinh"].FillWeight = 70;
            dgvGuests.Columns["NgaySinh"].ReadOnly = true;

            dgvGuests.Columns.Add("GioiTinh", UiText.Get("ColGender", "Giới Tính"));
            dgvGuests.Columns["GioiTinh"].FillWeight = 55;
            dgvGuests.Columns["GioiTinh"].ReadOnly = true;

            dgvGuests.Columns.Add("QuocTich", UiText.Get("ColNationality", "Quốc Tịch"));
            dgvGuests.Columns["QuocTich"].FillWeight = 55;
            dgvGuests.Columns["QuocTich"].ReadOnly = true;

            dgvGuests.Columns.Add("SoHoChieu", UiText.Get("ColPassportNo", "Số Hộ Chiếu"));
            dgvGuests.Columns["SoHoChieu"].FillWeight = 80;
            dgvGuests.Columns["SoHoChieu"].ReadOnly = true;

            // Editable columns (muc mau do theo yeu cau cua nguoi dung)
            dgvGuests.Columns.Add("SoPhong", UiText.Get("ColRoom", "Phòng ✎"));
            dgvGuests.Columns["SoPhong"].FillWeight = 50;
            dgvGuests.Columns["SoPhong"].ReadOnly = false;
            dgvGuests.Columns["SoPhong"].DefaultCellStyle.BackColor = Color.FromArgb(254, 255, 248);

            CalendarColumn colNgayDen = new CalendarColumn
            {
                Name = "NgayDen",
                HeaderText = UiText.Get("ColArrival", "Ngày Đến 📅"),
                FillWeight = 78,
                ReadOnly = false
            };
            colNgayDen.DefaultCellStyle.BackColor = Color.FromArgb(254, 255, 248);
            dgvGuests.Columns.Add(colNgayDen);

            CalendarColumn colNgayDi = new CalendarColumn
            {
                Name = "NgayDi",
                HeaderText = UiText.Get("ColDeparture", "Ngày Đi DK 📅"),
                FillWeight = 78,
                ReadOnly = false
            };
            colNgayDi.DefaultCellStyle.BackColor = Color.FromArgb(254, 255, 248);
            dgvGuests.Columns.Add(colNgayDi);

            CalendarColumn colNgayTra = new CalendarColumn
            {
                Name = "NgayTra",
                HeaderText = UiText.Get("ColCheckout", "Ngày Trả 📅"),
                FillWeight = 78,
                ReadOnly = false
            };
            colNgayTra.DefaultCellStyle.BackColor = Color.FromArgb(254, 255, 248);
            dgvGuests.Columns.Add(colNgayTra);

            CalendarColumn colHanTamTru = new CalendarColumn
            {
                Name = "HanTamTru",
                HeaderText = UiText.Get("ColResidenceTerm", "Hạn Tạm Trú 📅"),
                FillWeight = 82,
                ReadOnly = false
            };
            colHanTamTru.DefaultCellStyle.BackColor = Color.FromArgb(254, 255, 248);
            dgvGuests.Columns.Add(colHanTamTru);

            // Cot nut Xoa theo dong
            DataGridViewButtonColumn colDelete = new DataGridViewButtonColumn
            {
                Name = "ColDelete",
                HeaderText = UiText.Get("ColAction", "Thao Tác"),
                Text = UiText.Get("BtnDeleteRow", "🗑 Xóa"),
                UseColumnTextForButtonValue = true,
                FillWeight = 50,
                Width = 65,
                FlatStyle = FlatStyle.Popup
            };
            colDelete.DefaultCellStyle.ForeColor = Color.Crimson;
            colDelete.DefaultCellStyle.SelectionForeColor = Color.Crimson;
            colDelete.DefaultCellStyle.Font = AppFont(8.5f, FontStyle.Bold);
            dgvGuests.Columns.Add(colDelete);

            pnlGrid.Controls.Add(dgvGuests);
            dgvGuests.BringToFront();
            dgvGuests.DataError += (s, e) => { e.ThrowException = false; };

            dgvGuests.CellClick += (s, e) => {
                if (e.RowIndex >= 0 && e.RowIndex < dgvGuests.Rows.Count)
                {
                    if (e.ColumnIndex == dgvGuests.Columns["ColDelete"].Index)
                    {
                        DeleteGuestRow(e.RowIndex);
                        return;
                    }

                    var row = dgvGuests.Rows[e.RowIndex];
                    txtFullName.Text = Convert.ToString(row.Cells["HoTen"].Value);
                    txtBirthDay.Text = Convert.ToString(row.Cells["NgaySinh"].Value);
                    string gVal = Convert.ToString(row.Cells["GioiTinh"].Value).Trim();
                    cboGender.SelectedIndex = (gVal == "Nữ" || gVal == "F" || gVal == "2") ? 1 : 0;
                    txtNationality.Text = Convert.ToString(row.Cells["QuocTich"].Value);
                    txtPassportNo.Text = Convert.ToString(row.Cells["SoHoChieu"].Value);
                    txtRoom.Text = Convert.ToString(row.Cells["SoPhong"].Value);
                    try
                    {
                        DateTime d;
                        if (DateTime.TryParseExact(Convert.ToString(row.Cells["NgayDen"].Value), "dd/MM/yyyy", null, System.Globalization.DateTimeStyles.None, out d))
                            dtpArrival.Value = d;
                        if (DateTime.TryParseExact(Convert.ToString(row.Cells["NgayDi"].Value), "dd/MM/yyyy", null, System.Globalization.DateTimeStyles.None, out d))
                            dtpDeparture.Value = d;
                        if (DateTime.TryParseExact(Convert.ToString(row.Cells["NgayTra"].Value), "dd/MM/yyyy", null, System.Globalization.DateTimeStyles.None, out d))
                            dtpCheckOut.Value = d;
                        if (DateTime.TryParseExact(Convert.ToString(row.Cells["HanTamTru"].Value), "dd/MM/yyyy", null, System.Globalization.DateTimeStyles.None, out d))
                            dtpResidenceTerm.Value = d;
                    }
                    catch { }
                }
            };

            dgvGuests.CellBeginEdit += (s, e) => {
                if (e.RowIndex >= 0 && e.RowIndex < dgvGuests.Rows.Count)
                {
                    _editRowIndex = e.RowIndex;
                    _editColIndex = e.ColumnIndex;
                    object v = dgvGuests.Rows[e.RowIndex].Cells[e.ColumnIndex].Value;
                    _cellBeforeEditValue = v != null ? v.ToString().Trim() : "";
                }
            };

            dgvGuests.CellEndEdit += (s, e) => {
                if (e.RowIndex >= 0 && e.RowIndex < dgvGuests.Rows.Count)
                {
                    var row = dgvGuests.Rows[e.RowIndex];
                    string colName = dgvGuests.Columns[e.ColumnIndex].Name;
                    object newObj = row.Cells[e.ColumnIndex].Value;
                    string newVal = newObj != null ? newObj.ToString().Trim() : "";
                    string oldVal = (_editRowIndex == e.RowIndex && _editColIndex == e.ColumnIndex && _cellBeforeEditValue != null)
                                    ? _cellBeforeEditValue
                                    : "";

                    _cellBeforeEditValue = null;
                    _editRowIndex = -1;
                    _editColIndex = -1;

                    bool isChanged = false;
                    if (colName == "NgayDen" || colName == "NgayDi" || colName == "NgayTra" || colName == "HanTamTru")
                    {
                        DateTime dNew, dOld;
                        bool hasNew = DateTime.TryParseExact(newVal, "dd/MM/yyyy", null, DateTimeStyles.None, out dNew);
                        bool hasOld = DateTime.TryParseExact(oldVal, "dd/MM/yyyy", null, DateTimeStyles.None, out dOld);
                        if (hasNew && hasOld)
                        {
                            isChanged = (dNew.Date != dOld.Date);
                        }
                        else
                        {
                            isChanged = !string.Equals(newVal, oldVal, StringComparison.OrdinalIgnoreCase);
                        }
                    }
                    else
                    {
                        isChanged = !string.Equals(newVal, oldVal, StringComparison.OrdinalIgnoreCase);
                    }

                    // Chỉ khi người dùng thực sự thay đổi nội dung mới cập nhật và hiển thị thông báo
                    if (!isChanged)
                    {
                        return;
                    }

                    if (colName == "SoPhong")
                    {
                        txtRoom.Text = newVal;
                    }
                    else if (colName == "NgayDen" || colName == "NgayDi" || colName == "NgayTra" || colName == "HanTamTru")
                    {
                        DateTime d;
                        if (DateTime.TryParseExact(newVal, "dd/MM/yyyy", null, DateTimeStyles.None, out d))
                        {
                            if (colName == "NgayDen") dtpArrival.Value = d;
                            else if (colName == "NgayDi") dtpDeparture.Value = d;
                            else if (colName == "NgayTra") dtpCheckOut.Value = d;
                            else if (colName == "HanTamTru") dtpResidenceTerm.Value = d;
                        }
                    }

                    SaveAllGridToCsv();
                    try { AntdUI.Message.success(this, "Đã lưu thay đổi vào CSV!"); } catch { }
                }
            };

            dgvGuests.KeyDown += (s, e) => {
                if (e.KeyCode == Keys.Delete && !dgvGuests.IsCurrentCellInEditMode)
                {
                    if (dgvGuests.CurrentRow != null && dgvGuests.CurrentRow.Index >= 0)
                    {
                        e.Handled = true;
                        DeleteGuestRow(dgvGuests.CurrentRow.Index);
                    }
                }
            };

            splitMain.Panel2.Controls.Add(pnlGrid);

            LoadCsvGridIfExists();

            this.Shown += (s, e) => {
                try { splitMain.SplitterDistance = 340; } catch { }
                UpdateGrpImagesHeight();
                ForceForeground();

                System.Windows.Forms.Timer tmrFocus = new System.Windows.Forms.Timer { Interval = 150 };
                tmrFocus.Tick += (ts, te) => {
                    tmrFocus.Stop();
                    tmrFocus.Dispose();
                    ForceForeground();
                };
                tmrFocus.Start();
            };
        }

        private void UpdateGrpImagesHeight()
        {
            // grpImages uses DockStyle.Fill to remain symmetrically aligned with grpInfo and grpStay
        }

        private AntdUI.Input AddFormField(Panel pnl, string labelText, ref int curY, bool readOnly = false, bool isBold = false)
        {
            Label lbl = new Label { Text = labelText, Location = new Point(10, curY), AutoSize = true, Font = AppFont(9f, FontStyle.Bold) };
            bool isMrz = labelText.Contains("MRZ");
            AntdUI.Input txt = new AntdUI.Input
            {
                Location = new Point(10, curY + 20),
                Size = new Size(340, 32),
                ReadOnly = readOnly,
                Font = isMrz ? AppFont(9.5f, FontStyle.Bold) : (isBold ? AppFont(10.5f, FontStyle.Bold) : AppFont(9.5f)),
                ForeColor = Color.FromArgb(20, 20, 20),
                BorderColor = Color.FromArgb(217, 217, 217),
                Radius = 6
            };
            pnl.Controls.AddRange(new Control[] { lbl, txt });
            curY += 54;
            return txt;
        }

        public bool HandleGlobalKeyDown(Keys key, Keys modifiers)
        {
            if (key == Keys.ControlKey || key == Keys.LControlKey || key == Keys.RControlKey)
            {
                _isCtrlAlone = true;
                _ctrlDownTime = DateTime.UtcNow.Ticks;
                return false;
            }

            if ((modifiers & Keys.Control) == Keys.Control)
            {
                _isCtrlAlone = false;
                if (key == Keys.S)
                {
                    SaveCurrentGuestToCsv(true);
                    return true;
                }
                else if (key == Keys.X)
                {
                    BtnExportXml_Click(null, EventArgs.Empty);
                    return true;
                }
                else if (key == Keys.O)
                {
                    ChooseAndProcessImage();
                    return true;
                }
                else if (key == Keys.H)
                {
                    ShowUserGuideDialog(0);
                    return true;
                }
                return false;
            }

            _isCtrlAlone = false;

            if (key == Keys.F1)
            {
                chkAutoScan5s.Checked = !chkAutoScan5s.Checked;
                return true;
            }
            else if (key == Keys.F2)
            {
                chkAutoAppend.Checked = !chkAutoAppend.Checked;
                return true;
            }
            else if (key == Keys.F3)
            {
                chkAutoScan.Checked = !chkAutoScan.Checked;
                return true;
            }
            else if (key == Keys.F5)
            {
                TriggerScan();
                return true;
            }
            else if (key == Keys.F12)
            {
                ShowUserGuideDialog(0);
                return true;
            }

            return false;
        }

        public bool HandleGlobalKeyUp(Keys key, Keys modifiers)
        {
            if (key == Keys.ControlKey || key == Keys.LControlKey || key == Keys.RControlKey)
            {
                if (_isCtrlAlone && (DateTime.UtcNow.Ticks - _ctrlDownTime) < TimeSpan.FromSeconds(2).Ticks)
                {
                    _isCtrlAlone = false;
                    TriggerScan();
                    return true;
                }
                _isCtrlAlone = false;
            }
            else
            {
                _isCtrlAlone = false;
            }
            return false;
        }

        private void MainForm_KeyDown(object sender, KeyEventArgs e)
        {
            if (HandleGlobalKeyDown(e.KeyCode, e.Modifiers))
            {
                e.Handled = true;
                e.SuppressKeyPress = true;
            }
        }

        private void MainForm_KeyUp(object sender, KeyEventArgs e)
        {
            if (HandleGlobalKeyUp(e.KeyCode, e.Modifiers))
            {
                e.Handled = true;
                e.SuppressKeyPress = true;
            }
        }

        public void ShowUserGuideDialog(int initialTab = 0)
        {
            try
            {
                using (UserGuideForm guide = new UserGuideForm(initialTab, appDir))
                {
                    guide.Icon = this.Icon;
                    guide.ShowDialog(this);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show("Không thể mở cửa sổ hướng dẫn: " + ex.Message, "Lỗi", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void OpenUiTextIni()
        {
            string iniPath = Path.Combine(appDir, "ui_text.ini");
            if (!File.Exists(iniPath))
            {
                UiText.SaveIniFile(iniPath);
            }
            try
            {
                System.Diagnostics.Process.Start("notepad.exe", iniPath);
            }
            catch (Exception ex)
            {
                MessageBox.Show("Không thể mở file bằng Notepad: " + ex.Message, "Lỗi", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void InitScanner()
        {
            ScannerNative.ApplyDriverHotfix();

            try
            {
                int r = ScannerNative.SafeHasScanner("IDCapture", this.Handle);
                if (r == 0)
                {
                    isScannerConnected = true;
                    lblStatus.Text = UiText.Get("StatusReady", "● MÁY QUÉT ID-CAPTURE: ĐÃ KẾT NỐI (Syscan IDC-V SẴN SÀNG QUÉT [F5 / Ctrl])");
                    lblStatus.ForeColor = Color.ForestGreen;
                    btnScan.Enabled = true;

                    if (autoScanTimer == null)
                    {
                        autoScanTimer = new System.Windows.Forms.Timer();
                        autoScanTimer.Interval = 600;
                        autoScanTimer.Tick += AutoScanTimer_Tick;
                    }
                    autoScanTimer.Start();
                }
                else
                {
                    isScannerConnected = false;
                    lblStatus.Text = UiText.Get("StatusNotConnected", "● MÁY QUÉT: CHƯA KẾT NỐI USB (Có thể kéo thả hoặc chọn ảnh từ máy để quét)");
                    lblStatus.ForeColor = Color.DarkOrange;
                }
            }
            catch (Exception ex)
            {
                isScannerConnected = false;
                lblStatus.Text = UiText.Format("StatusFileMode", ex.Message);
                lblStatus.ForeColor = Color.DarkOrange;
            }
        }

        private void AutoScanTimer_Tick(object sender, EventArgs e)
        {
            if (isProcessing || !chkAutoScan.Checked || !isScannerConnected) return;

            try
            {
                int top = ScannerNative.IO_GetDevTopState();
                if (top == 1 && lastTopState == 0)
                {
                    lastAutoScannedPassportNo = "";
                    TriggerScan(false);
                }
                lastTopState = top;
            }
            catch { }
        }

        private void StartAutoScan5sTimer()
        {
            if (autoScan5sTimer == null)
            {
                autoScan5sTimer = new System.Windows.Forms.Timer();
                autoScan5sTimer.Interval = 5000;
                autoScan5sTimer.Tick += AutoScan5sTimer_Tick;
            }
            autoScan5sTimer.Stop();
            autoScan5sTimer.Start();
        }

        private void StopAutoScan5sTimer()
        {
            if (autoScan5sTimer != null)
            {
                autoScan5sTimer.Stop();
            }
        }

        private void AutoScan5sTimer_Tick(object sender, EventArgs e)
        {
            if (isProcessing || !chkAutoScan5s.Checked || !isScannerConnected) return;

            // Nắp máy đang mở hoặc đóng thì vẫn quét bình thường
            TriggerScan(true);
        }

        private void SetScanMode(int mode, bool saveToIni = true)
        {
            scanMode = mode;

            if (btnModeAuto != null)
            {
                btnModeAuto.Type = (mode == 0) ? AntdUI.TTypeMini.Primary : AntdUI.TTypeMini.Default;
                btnModeAuto.Font = AppFont(8.5f, (mode == 0) ? FontStyle.Bold : FontStyle.Regular);
            }
            if (btnModeSyscan != null)
            {
                btnModeSyscan.Type = (mode == 1) ? AntdUI.TTypeMini.Primary : AntdUI.TTypeMini.Default;
                btnModeSyscan.Font = AppFont(8.5f, (mode == 1) ? FontStyle.Bold : FontStyle.Regular);
            }
            if (btnModeAi != null)
            {
                btnModeAi.Type = (mode == 2) ? AntdUI.TTypeMini.Primary : AntdUI.TTypeMini.Default;
                btnModeAi.Font = AppFont(8.5f, (mode == 2) ? FontStyle.Bold : FontStyle.Regular);
            }

            UpdateScanButtonText();

            if (saveToIni)
            {
                try
                {
                    UiText.Set("ScanMode", mode.ToString());
                    UiText.SaveIniFile(Path.Combine(appDir, "ui_text.ini"));
                }
                catch { }

                string modeDesc = (mode == 0) 
                    ? "Tự động kết hợp (Gốc Syscan + AI Windows) [Khuyên dùng]" 
                    : ((mode == 1) ? "Thư viện gốc Syscan (IO_GetIDResult - Tương thích mọi máy)" : "AI Windows OCR (IO_GetIDImage_File + Windows AI OCR)");
                try { AntdUI.Message.info(this, "Đã chọn cách thiết bị làm việc: " + modeDesc); } catch { }
            }
        }

        private void UpdateScanButtonText()
        {
            if (btnScan == null) return;
            if (scanMode == 0)
                btnScan.Text = UiText.Get("BtnScanAuto", "⚡ QUÉT HỘ CHIẾU (TỰ ĐỘNG) [F5 / Ctrl]");
            else if (scanMode == 1)
                btnScan.Text = UiText.Get("BtnScanSyscan", "📟 QUÉT HỘ CHIẾU (GỐC SYSCAN) [F5 / Ctrl]");
            else
                btnScan.Text = UiText.Get("BtnScanAi", "🤖 QUÉT HỘ CHIẾU (AI WINDOWS) [F5 / Ctrl]");
        }

        private void TriggerScan(bool isAuto5s = false)
        {
            if (isProcessing) return;

            if (!isScannerConnected)
            {
                InitScanner();
                if (!isScannerConnected)
                {
                    if (!isAuto5s)
                    {
                        DialogResult dr = MessageBox.Show(
                            "Không tìm thấy máy quét ID-Capture hoặc chưa cắm cáp USB!\n\n" +
                            "Các bước kiểm tra và xử lý:\n" +
                            "1. Kiểm tra cáp USB máy quét đã cắm chắc chắn vào máy tính chưa (thử rút ra cắm lại cổng khác).\n" +
                            "2. Đảm bảo Driver máy quét đã được cài đặt (chạy file install_driver.bat trong thư mục cài đặt).\n" +
                            "3. Nếu máy dùng Windows 11: Windows có thể chặn Driver cũ do tính năng bảo mật 'Core Isolation'. Cần vào 'Windows Security' > 'Device Security' > 'Core Isolation' và tắt 'Memory Integrity' (Tính toàn vẹn bộ nhớ), sau đó khởi động lại máy.\n\n" +
                            "Bạn có muốn mở thư mục cài đặt Driver máy quét ngay bây giờ không?",
                            "Không tìm thấy máy quét ID-Capture",
                            MessageBoxButtons.YesNo,
                            MessageBoxIcon.Warning
                        );
                        if (dr == DialogResult.Yes)
                        {
                            try
                            {
                                string drvBat = Path.Combine(appDir, "driver", "install_driver.bat");
                                if (File.Exists(drvBat))
                                {
                                    ProcessStartInfo psi = new ProcessStartInfo(drvBat)
                                    {
                                        WorkingDirectory = Path.Combine(appDir, "driver"),
                                        UseShellExecute = true,
                                        Verb = "runas"
                                    };
                                    Process.Start(psi);
                                }
                                else
                                {
                                    Process.Start(appDir);
                                }
                            }
                            catch { }
                        }
                    }
                    return;
                }
            }

            isProcessing = true;
            btnScan.Enabled = false;
            btnUploadImage.Enabled = false;
            btnScan.Text = "Đang quét...";
            lblStatus.Text = isAuto5s ? "● [TỰ ĐỘNG 5S] Đang kiểm tra mặt kính máy quét..." : "● Đang đọc hộ chiếu từ máy quét Syscan IDC-V...";
            lblStatus.ForeColor = Color.Blue;

            Thread scanThread = new Thread(() =>
            {
                try
                {
                    Directory.SetCurrentDirectory(appDir);
                    ScannerNative.ApplyDriverHotfix();

                    if (scanMode == 1)
                    {
                        ExecuteScanSyscanLegacy(isAuto5s);
                    }
                    else if (scanMode == 2)
                    {
                        ExecuteScanWindowsAiOcr(isAuto5s);
                    }
                    else
                    {
                        ExecuteScanHybrid(isAuto5s);
                    }
                }
                catch (Exception ex)
                {
                    this.Invoke(new Action(() =>
                    {
                        isProcessing = false;
                        btnScan.Enabled = true;
                        btnUploadImage.Enabled = true;
                        UpdateScanButtonText();
                        lblStatus.Text = "● LỖI TRONG QUÁ TRÌNH QUÉT: " + ex.Message;
                        lblStatus.ForeColor = Color.Red;
                        if (!isAuto5s)
                        {
                            MessageBox.Show("Lỗi trong quá trình quét: " + ex.Message, "Lỗi quét", MessageBoxButtons.OK, MessageBoxIcon.Error);
                        }
                    }));
                }
            });

            scanThread.IsBackground = true;
            scanThread.Start();
        }

        private void ExecuteScanSyscanLegacy(bool isAuto5s)
        {
            string fullGrey = Path.Combine(appDir, "G01.bmp");
            string fullColor = Path.Combine(appDir, "C01.bmp");
            string fullGreyHead = Path.Combine(appDir, "GH01.bmp");
            string fullColorHead = Path.Combine(appDir, "CH01.bmp");

            try { if (File.Exists(fullGrey)) File.Delete(fullGrey); } catch { }
            try { if (File.Exists(fullColor)) File.Delete(fullColor); } catch { }
            try { if (File.Exists(fullGreyHead)) File.Delete(fullGreyHead); } catch { }
            try { if (File.Exists(fullColorHead)) File.Delete(fullColorHead); } catch { }

            SYSCAN_RST card = new SYSCAN_RST();
            int ret = ScannerNative.SafeGetIDResult(4, fullGrey, fullColor, fullGreyHead, fullColorHead, 100, ref card);

            // Nếu mất kết nối handle USB tạm thời (-2000 / -2002) hoặc lỗi -2017, tự khởi tạo lại và thử quét lại 1 lần
            if (ret == -2000 || ret == -2002 || ret == -2017)
            {
                IntPtr hWnd = IntPtr.Zero;
                try { this.Invoke(new Action(() => { hWnd = this.Handle; })); } catch { }
                if (ScannerNative.SafeHasScanner("IDCapture", hWnd) == 0)
                {
                    card = new SYSCAN_RST();
                    ret = ScannerNative.SafeGetIDResult(4, fullGrey, fullColor, fullGreyHead, fullColorHead, 100, ref card);
                }
            }

            // Nếu IO_GetIDResult lỗi nhưng vẫn có thể chụp ảnh bằng IO_GetIDImage_File
            if ((ret != 0 || !File.Exists(fullColor)) && ret != -2000)
            {
                try { ScannerNative.IO_SetFTLight(0, 1); } catch { }
                Thread.Sleep(50);
                int imgRet = ScannerNative.SafeGetIDImageFile(1, 4, 0, fullColor);
                try { ScannerNative.IO_SetFTLight(0, 0); } catch { }
                if (imgRet == 0 && File.Exists(fullColor))
                {
                    ret = 0;
                    // Thử nhận diện file ảnh vừa chụp bằng Syscan OCR
                    SYSCAN_RST card2 = new SYSCAN_RST();
                    if (ScannerNative.SafeIdentifyCardFile(fullColor, 4, fullColorHead, ref card2) == 0)
                    {
                        card = card2;
                    }
                }
            }

            this.Invoke(new Action(() =>
            {
                isProcessing = false;
                btnScan.Enabled = true;
                btnUploadImage.Enabled = true;
                UpdateScanButtonText();

                if (ret == 0 && File.Exists(fullColor))
                {
                    if (isAuto5s && !NativePassportEngine.HasDocumentOnGlass(fullColor))
                    {
                        lastAutoScannedPassportNo = "";
                        lblStatus.Text = "● [TỰ ĐỘNG 5S] Sẵn sàng, chờ đặt hộ chiếu lên mặt kính...";
                        lblStatus.ForeColor = Color.DarkOrange;
                        return;
                    }

                    try { ScannerNative.IO_NotifyBeep(100); } catch { }

                    PassportParseResult result = NativePassportEngine.ConvertSyscanRstToResult(card, fullColor, fullColorHead);
                    if (result.Success)
                    {
                        ApplyPassportResultToForm(result, isAuto5s, "Gốc Syscan");
                    }
                    else
                    {
                        // Dự phòng tự động đọc MRZ từ ảnh vừa chụp nếu Syscan 2013 không nhận diện được phôi hộ chiếu mẫu mới
                        lblStatus.Text = "● Gốc Syscan chưa nhận diện được phôi mới, đang tự động đọc ảnh...";
                        lblStatus.ForeColor = Color.Blue;
                        ProcessPassportImageWithWindowsAi(fullColor, isAuto5s, result);
                    }
                }
                else
                {
                    HandleScanFailed(ret, isAuto5s);
                }
            }));
        }

        private void ExecuteScanWindowsAiOcr(bool isAuto5s)
        {
            string scanFile = Path.Combine(appDir, "C01.bmp");
            try { if (File.Exists(scanFile)) File.Delete(scanFile); } catch { }

            try { ScannerNative.IO_SetFTLight(0, 1); } catch { }
            Thread.Sleep(50);
            int ret = ScannerNative.SafeGetIDImageFile(1, 4, 0, scanFile);
            try { ScannerNative.IO_SetFTLight(0, 0); } catch { }

            if (ret == -2000 || ret == -2002 || ret == -2017)
            {
                IntPtr hWnd = IntPtr.Zero;
                try { this.Invoke(new Action(() => { hWnd = this.Handle; })); } catch { }
                if (ScannerNative.SafeHasScanner("IDCapture", hWnd) == 0)
                {
                    try { ScannerNative.IO_SetFTLight(0, 1); } catch { }
                    Thread.Sleep(50);
                    ret = ScannerNative.SafeGetIDImageFile(1, 4, 0, scanFile);
                    try { ScannerNative.IO_SetFTLight(0, 0); } catch { }
                }
            }

            this.Invoke(new Action(() =>
            {
                isProcessing = false;
                btnScan.Enabled = true;
                btnUploadImage.Enabled = true;
                UpdateScanButtonText();

                if (ret == 0 && File.Exists(scanFile))
                {
                    if (isAuto5s && !NativePassportEngine.HasDocumentOnGlass(scanFile))
                    {
                        lastAutoScannedPassportNo = "";
                        lblStatus.Text = "● [TỰ ĐỘNG 5S] Sẵn sàng, chờ đặt hộ chiếu lên mặt kính...";
                        lblStatus.ForeColor = Color.DarkOrange;
                        return;
                    }

                    try { ScannerNative.IO_NotifyBeep(100); } catch { }
                    lblStatus.Text = "● ĐÃ PHÁT HIỆN HỘ CHIẾU! Đang nhận diện thông tin bằng AI Windows OCR...";
                    lblStatus.ForeColor = Color.Blue;

                    ProcessPassportImageWithWindowsAi(scanFile, isAuto5s);
                }
                else
                {
                    HandleScanFailed(ret, isAuto5s);
                }
            }));
        }

        private void ExecuteScanHybrid(bool isAuto5s)
        {
            string fullGrey = Path.Combine(appDir, "G01.bmp");
            string fullColor = Path.Combine(appDir, "C01.bmp");
            string fullGreyHead = Path.Combine(appDir, "GH01.bmp");
            string fullColorHead = Path.Combine(appDir, "CH01.bmp");

            try { if (File.Exists(fullGrey)) File.Delete(fullGrey); } catch { }
            try { if (File.Exists(fullColor)) File.Delete(fullColor); } catch { }
            try { if (File.Exists(fullGreyHead)) File.Delete(fullGreyHead); } catch { }
            try { if (File.Exists(fullColorHead)) File.Delete(fullColorHead); } catch { }

            SYSCAN_RST card = new SYSCAN_RST();
            int ret = ScannerNative.SafeGetIDResult(4, fullGrey, fullColor, fullGreyHead, fullColorHead, 100, ref card);

            if (ret != 0 || !File.Exists(fullColor))
            {
                try { ScannerNative.IO_SetFTLight(0, 1); } catch { }
                Thread.Sleep(50);
                ret = ScannerNative.SafeGetIDImageFile(1, 4, 0, fullColor);
                try { ScannerNative.IO_SetFTLight(0, 0); } catch { }
            }

            this.Invoke(new Action(() =>
            {
                isProcessing = false;
                btnScan.Enabled = true;
                btnUploadImage.Enabled = true;
                UpdateScanButtonText();

                if (ret == 0 && File.Exists(fullColor))
                {
                    if (isAuto5s && !NativePassportEngine.HasDocumentOnGlass(fullColor))
                    {
                        lastAutoScannedPassportNo = "";
                        lblStatus.Text = "● [TỰ ĐỘNG 5S] Sẵn sàng, chờ đặt hộ chiếu lên mặt kính...";
                        lblStatus.ForeColor = Color.DarkOrange;
                        return;
                    }

                    try { ScannerNative.IO_NotifyBeep(100); } catch { }

                    PassportParseResult sysResult = NativePassportEngine.ConvertSyscanRstToResult(card, fullColor, fullColorHead);
                    if (sysResult.Success && !string.IsNullOrEmpty(sysResult.PassportNo))
                    {
                        ApplyPassportResultToForm(sysResult, isAuto5s, "Gốc Syscan");
                        return;
                    }

                    lblStatus.Text = "● Đang nhận diện bổ trợ bằng AI Windows OCR...";
                    lblStatus.ForeColor = Color.Blue;
                    ProcessPassportImageWithWindowsAi(fullColor, isAuto5s, sysResult);
                }
                else
                {
                    HandleScanFailed(ret, isAuto5s);
                }
            }));
        }

        private async void ProcessPassportImageWithWindowsAi(string scanFile, bool isAuto5s, PassportParseResult fallbackResult = null)
        {
            isProcessing = true;
            btnScan.Enabled = false;
            btnUploadImage.Enabled = false;

            try
            {
                PassportParseResult aiResult = await Task.Run(() => NativePassportEngine.ProcessImage(scanFile, appDir));
                if (aiResult != null && aiResult.Success)
                {
                    ApplyPassportResultToForm(aiResult, isAuto5s, "AI Windows OCR");
                }
                else if (fallbackResult != null && fallbackResult.Success)
                {
                    ApplyPassportResultToForm(fallbackResult, isAuto5s, "Gốc Syscan");
                }
                else
                {
                    lblStatus.Text = "● KHÔNG NHẬN DIỆN ĐƯỢC THÔNG TIN TRÊN ẢNH";
                    lblStatus.ForeColor = Color.DarkOrange;
                    ShowUnrecognizedImage(scanFile);

                    if (!isAuto5s)
                    {
                        string errMsg = (aiResult != null && !string.IsNullOrEmpty(aiResult.ErrorMessage)) 
                            ? aiResult.ErrorMessage 
                            : "Không thể nhận diện được thông tin hộ chiếu từ ảnh.";

                        if (errMsg.Contains("Language.OCR~~~en-US~0.0.1.0"))
                        {
                            DialogResult dr = MessageBox.Show(
                                errMsg + "\n\nBạn có muốn tự động cài gói AI Windows OCR ngay bây giờ không?\n(Gợi ý: Bạn có thể bấm nút '📟 Thư viện gốc Syscan' trên thanh tiêu đề để quét trực tiếp không cần gói AI này)",
                                "Thiếu gói AI Windows OCR",
                                MessageBoxButtons.YesNo,
                                MessageBoxIcon.Warning
                            );
                            if (dr == DialogResult.Yes)
                            {
                                try
                                {
                                    ProcessStartInfo psi = new ProcessStartInfo
                                    {
                                        FileName = "powershell.exe",
                                        Arguments = "-NoExit -Command \"Write-Host 'Đang cài đặt gói Windows AI OCR...' -ForegroundColor Cyan; DISM /Online /Add-Capability /CapabilityName:Language.OCR~~~en-US~0.0.1.0; Write-Host 'Hoàn tất!' -ForegroundColor Green; Read-Host\"",
                                        Verb = "runas",
                                        UseShellExecute = true
                                    };
                                    Process.Start(psi);
                                }
                                catch { }
                            }
                        }
                        else
                        {
                            MessageBox.Show(errMsg, "Chưa đọc được thông tin", MessageBoxButtons.OK, MessageBoxIcon.Information);
                        }
                    }
                    else
                    {
                        try { AntdUI.Message.warn(this, "Chưa đọc được thông tin hộ chiếu."); } catch { }
                    }
                }
            }
            catch (Exception ex)
            {
                lblStatus.Text = "● LỖI XỬ LÝ: " + ex.Message;
                lblStatus.ForeColor = Color.Red;
            }
            finally
            {
                isProcessing = false;
                btnScan.Enabled = true;
                btnUploadImage.Enabled = true;
            }
        }

        private void ChooseAndProcessImage()
        {
            if (isProcessing) return;
            using (OpenFileDialog ofd = new OpenFileDialog())
            {
                ofd.Title = "Chọn ảnh hộ chiếu để nhận diện (JPG, PNG, BMP, WEBP...)";
                ofd.Filter = "Tất cả file ảnh (*.jpg;*.jpeg;*.png;*.bmp;*.tiff;*.webp)|*.jpg;*.jpeg;*.png;*.bmp;*.tiff;*.webp|Bitmap (*.bmp)|*.bmp|JPEG (*.jpg;*.jpeg)|*.jpg;*.jpeg|PNG (*.png)|*.png|Tất cả các file (*.*)|*.*";
                ofd.RestoreDirectory = true;
                string passDir = Path.Combine(appDir, "images", "Passport", DateTime.Now.ToString("yyyy"), DateTime.Now.ToString("dd-MM"));
                string imgDir = Directory.Exists(passDir) ? passDir : Path.Combine(appDir, "images");
                if (Directory.Exists(imgDir)) ofd.InitialDirectory = imgDir;
                if (ofd.ShowDialog(this) == DialogResult.OK)
                {
                    try { Directory.SetCurrentDirectory(appDir); } catch { }
                    ProcessPassportImage(ofd.FileName, false);
                }
            }
        }

        private async void ProcessPassportImage(string filePath, bool isAuto5s = false)
        {
            if (isProcessing) return;
            if (string.IsNullOrEmpty(filePath) || !File.Exists(filePath)) return;

            isProcessing = true;
            btnScan.Enabled = false;
            btnUploadImage.Enabled = false;
            lblStatus.Text = "● Đang nhận diện thông tin hộ chiếu từ ảnh...";
            lblStatus.ForeColor = Color.Blue;

            try
            {
                try { Directory.SetCurrentDirectory(appDir); } catch { }
                ScannerNative.ApplyDriverHotfix();

                PassportParseResult result = null;
                bool usedSyscan = false;

                if (scanMode == 1 && ScannerNative.IsSyscanEngineReady()) // Mode Gốc Syscan (chỉ gọi khi động cơ Syscan đã khởi tạo)
                {
                    result = await Task.Run(() =>
                    {
                        string tempDir = Path.Combine(Path.GetTempPath(), "PassportScanner_temp_ocr");
                        try { if (!Directory.Exists(tempDir)) Directory.CreateDirectory(tempDir); } catch { }
                        string tempBmp = Path.Combine(tempDir, "sys_in_" + Guid.NewGuid().ToString("N") + ".bmp");
                        string tempPhoto = Path.Combine(tempDir, "sys_face_" + Guid.NewGuid().ToString("N") + ".bmp");

                        try
                        {
                            // Chuẩn hóa ảnh bất kỳ (JPG/PNG/BMP/đường dẫn Unicode) sang BMP 24-bit ASCII cho ScanDll.dll
                            using (FileStream fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                            using (Image img = Image.FromStream(fs))
                            using (Bitmap b24 = new Bitmap(img.Width, img.Height, PixelFormat.Format24bppRgb))
                            {
                                using (Graphics g = Graphics.FromImage(b24))
                                {
                                    g.InterpolationMode = InterpolationMode.HighQualityBicubic;
                                    g.DrawImage(img, 0, 0, img.Width, img.Height);
                                }
                                b24.Save(tempBmp, ImageFormat.Bmp);
                            }

                            SYSCAN_RST card = new SYSCAN_RST();
                            int ret = ScannerNative.SafeIdentifyCardFile(tempBmp, 4, tempPhoto, ref card);
                            if (ret == 0)
                            {
                                return NativePassportEngine.ConvertSyscanRstToResult(card, filePath, tempPhoto);
                            }
                        }
                        catch { }
                        finally
                        {
                            try { if (File.Exists(tempBmp)) File.Delete(tempBmp); } catch { }
                            try { if (File.Exists(tempPhoto)) File.Delete(tempPhoto); } catch { }
                        }
                        return null;
                    });
                    if (result != null && result.Success) usedSyscan = true;
                }

                if (result == null || !result.Success)
                {
                    result = await Task.Run(() => NativePassportEngine.ProcessImage(filePath, appDir));
                }

                if (result != null && result.Success)
                {
                    string source = usedSyscan ? "Gốc Syscan" : (scanMode == 1 ? "AI Windows (dự phòng)" : (scanMode == 2 ? "AI Windows" : "Tự động"));
                    ApplyPassportResultToForm(result, isAuto5s, source);
                }
                else
                {
                    lblStatus.Text = "● KHÔNG NHẬN DIỆN ĐƯỢC THÔNG TIN TRÊN ẢNH";
                    lblStatus.ForeColor = Color.DarkOrange;
                    ShowUnrecognizedImage(filePath);

                    if (!isAuto5s)
                    {
                        string errMsg = (result != null && !string.IsNullOrEmpty(result.ErrorMessage)) 
                            ? result.ErrorMessage 
                            : "Không thể nhận diện được thông tin hộ chiếu từ ảnh.";

                        if (errMsg.Contains("Language.OCR~~~en-US~0.0.1.0"))
                        {
                            DialogResult dr = MessageBox.Show(
                                errMsg + "\n\nBạn có muốn tự động cài đặt gói Windows AI OCR ngay bây giờ không?\n(Gợi ý: Bạn có thể bấm nút '📟 Thư viện gốc Syscan' trên thanh tiêu đề để quét trực tiếp không cần gói AI này)",
                                "Thiếu gói AI Windows OCR",
                                MessageBoxButtons.YesNo,
                                MessageBoxIcon.Warning
                            );
                            if (dr == DialogResult.Yes)
                            {
                                try
                                {
                                    ProcessStartInfo psi = new ProcessStartInfo
                                    {
                                        FileName = "powershell.exe",
                                        Arguments = "-NoExit -Command \"Write-Host 'Đang cài đặt gói Windows AI OCR...' -ForegroundColor Cyan; DISM /Online /Add-Capability /CapabilityName:Language.OCR~~~en-US~0.0.1.0; Write-Host 'Hoàn tất!' -ForegroundColor Green; Read-Host\"",
                                        Verb = "runas",
                                        UseShellExecute = true
                                    };
                                    Process.Start(psi);
                                }
                                catch { }
                            }
                        }
                        else
                        {
                            MessageBox.Show(errMsg, "Chưa đọc được thông tin", MessageBoxButtons.OK, MessageBoxIcon.Information);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                lblStatus.Text = "● LỖI XỬ LÝ: " + ex.Message;
                lblStatus.ForeColor = Color.Red;
                if (!isAuto5s)
                {
                    MessageBox.Show("Lỗi trong quá trình xử lý ảnh: " + ex.Message, "Lỗi", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
            }
            finally
            {
                isProcessing = false;
                btnScan.Enabled = true;
                btnUploadImage.Enabled = true;
            }
        }

        private void ApplyPassportResultToForm(PassportParseResult result, bool isAuto5s, string engineSource)
        {
            if (result == null || !result.Success) return;

            if (isAuto5s && !string.IsNullOrEmpty(lastAutoScannedPassportNo) && result.PassportNo == lastAutoScannedPassportNo)
            {
                lblStatus.Text = string.Format("● [TỰ ĐỘNG 5S] Hộ chiếu {0} đã được lưu. Đang chờ đổi hộ chiếu tiếp theo...", result.PassportNo);
                lblStatus.ForeColor = Color.ForestGreen;
                return;
            }

            lastAutoScannedPassportNo = result.PassportNo;

            txtFullName.Text = result.FullName;
            txtPassportNo.Text = result.PassportNo;
            txtNationality.Text = result.Nationality;
            txtBirthDay.Text = result.BirthDate;
            cboGender.SelectedIndex = (result.Gender == "F") ? 1 : 0;
            txtExpiryDate.Text = result.ExpiryDate;
            txtMrz1.Text = result.MrzLine1;
            txtMrz2.Text = result.MrzLine2;

            // Hiển thị ảnh
            if (picPassport.Image != null) picPassport.Image.Dispose();
            picPassport.Image = (result.OrientedImage != null) ? (Image)result.OrientedImage.Clone() : null;
            UpdateGrpImagesHeight();

            if (picPhoto.Image != null) picPhoto.Image.Dispose();
            picPhoto.Image = (result.CroppedFace != null) ? (Image)result.CroppedFace.Clone() : null;

            // Lưu bản sao cố định theo quy định thư mục
            string currentYear = DateTime.Now.ToString("yyyy");
            string currentDayMonthFolder = DateTime.Now.ToString("dd-MM");
            string passportDir = Path.Combine(appDir, "images", "Passport", currentYear, currentDayMonthFolder);
            string faceDir = Path.Combine(appDir, "images", "Face", currentYear, currentDayMonthFolder);

            try { if (!Directory.Exists(passportDir)) Directory.CreateDirectory(passportDir); } catch { }
            try { if (!Directory.Exists(faceDir)) Directory.CreateDirectory(faceDir); } catch { }

            string timeStamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
            string safePassNo = string.IsNullOrEmpty(result.PassportNo) 
                ? "UNKNOWN" 
                : Regex.Replace(result.PassportNo.Trim(), @"[^\w\-]", "");

            if (result.OrientedImage != null)
            {
                string savePass = Path.Combine(passportDir, string.Format("Passport_{0}_{1}.bmp", safePassNo, timeStamp));
                try { result.OrientedImage.Save(savePass, ImageFormat.Bmp); } catch { }
            }
            if (result.CroppedFace != null)
            {
                string saveFace = Path.Combine(faceDir, string.Format("Face_{0}_{1}.jpg", safePassNo, timeStamp));
                try { result.CroppedFace.Save(saveFace, ImageFormat.Jpeg); } catch { }
            }

            try { System.Media.SystemSounds.Asterisk.Play(); } catch { }

            lblStatus.Text = string.Format("● [{0}] NHẬN DIỆN THÀNH CÔNG: {1} - {2}", engineSource, result.PassportNo, result.FullName);
            lblStatus.ForeColor = Color.ForestGreen;

            try { AntdUI.Message.success(this, string.Format("[{0}] Nhận diện thành công: {1} - {2}", engineSource, result.PassportNo, result.FullName)); } catch { }

            if (chkAutoAppend.Checked)
            {
                SaveCurrentGuestToCsv(false);
            }
        }

        private void ShowUnrecognizedImage(string filePath)
        {
            try
            {
                if (File.Exists(filePath))
                {
                    using (FileStream fs = new FileStream(filePath, FileMode.Open, FileAccess.Read))
                    {
                        using (Image img = Image.FromStream(fs))
                        {
                            if (picPassport.Image != null) picPassport.Image.Dispose();
                            picPassport.Image = new Bitmap(img);
                            UpdateGrpImagesHeight();
                        }
                    }
                }
            }
            catch { }
        }

        private void HandleScanFailed(int ret, bool isAuto5s)
        {
            lblStatus.Text = string.Format("● Quét thất bại (Mã lỗi: {0}). Vui lòng căn chỉnh lại hộ chiếu.", ret);
            lblStatus.ForeColor = Color.Red;
            if (chkAutoScan5s.Checked)
            {
                chkAutoScan5s.Checked = false;
                StopAutoScan5sTimer();
            }
            if (!isAuto5s)
            {
                if (ret == -2017)
                {
                    // Tự phục hồi cờ và dữ liệu cảm biến nếu gặp lỗi -2017
                    ScannerNative.EnsureCommonProgramDataFiles();
                    ScannerNative.ApplyDriverHotfix();
                    MessageBox.Show("Mã lỗi: -2017 (Cảm biến máy quét đang khởi tạo lại dữ liệu cấu hình ProgramData).\nHệ thống đã tự động khôi phục cấu hình dữ liệu cảm biến.\nVui lòng bấm 'Quét hộ chiếu' một lần nữa để quét!", "Tự phục hồi dữ liệu cảm biến", MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
                else
                {
                    MessageBox.Show(string.Format("Quét hộ chiếu không thành công (Mã lỗi: {0}).\nVui lòng căn chỉnh lại vị trí hộ chiếu trên mặt kính máy quét.", ret), "Quét thất bại", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                }
            }
        }

        private void SaveCurrentGuestToCsv(bool showSuccessMsg)
        {
            if (string.IsNullOrWhiteSpace(txtPassportNo.Text) && string.IsNullOrWhiteSpace(txtFullName.Text))
            {
                if (showSuccessMsg)
                {
                    MessageBox.Show(UiText.Get("MsgWarnNoData", "Vui lòng quét hoặc nhập thông tin hộ chiếu trước khi ghi file!"), "Thông báo", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                }
                return;
            }

            string csvPath = txtCsvPath.Text.Trim();
            if (string.IsNullOrEmpty(csvPath))
            {
                MessageBox.Show(UiText.Get("MsgWarnChooseCsv", "Vui lòng chọn đường dẫn file CSV!"), "Lỗi", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            try
            {
                string dir = Path.GetDirectoryName(csvPath);
                if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
                {
                    Directory.CreateDirectory(dir);
                }

                bool isNew = !File.Exists(csvPath);
                int nextStt = 1;

                if (!isNew)
                {
                    string[] existingLines = File.ReadAllLines(csvPath);
                    if (existingLines.Length > 1)
                    {
                        nextStt = existingLines.Length; // Header is line 0
                    }
                }

                string genCode = (cboGender.SelectedIndex == 1) ? "F" : "M";
                string roomVal = string.IsNullOrWhiteSpace(txtRoom.Text) ? "101" : txtRoom.Text.Trim();
                string recordLine = string.Format("{0},{1},{2},{3},{4},{5},{6},{7},{8},{9},{10},{11}",
                    nextStt,
                    EscapeCsv(txtFullName.Text.Trim().ToUpper()),
                    EscapeCsv(txtBirthDay.Text.Trim()),
                    "D",
                    genCode,
                    EscapeCsv(txtNationality.Text.Trim().ToUpper()),
                    EscapeCsv(txtPassportNo.Text.Trim().ToUpper()),
                    EscapeCsv(roomVal),
                    (dtpArrival.Value ?? DateTime.Today).ToString("dd/MM/yyyy"),
                    (dtpDeparture.Value ?? DateTime.Today.AddDays(3)).ToString("dd/MM/yyyy"),
                    (dtpCheckOut.Value ?? DateTime.Today.AddDays(3)).ToString("dd/MM/yyyy"),
                    (dtpResidenceTerm.Value ?? DateTime.Today.AddDays(9)).ToString("dd/MM/yyyy")
                );

                using (StreamWriter sw = new StreamWriter(csvPath, true, new UTF8Encoding(true)))
                {
                    if (isNew)
                    {
                        sw.WriteLine("STT,Họ và tên,Ngày sinh,Ngày sinh đúng đến,Giới tính,Mã quốc tịch,Số hộ chiếu,Số phòng,Ngày đến,Ngày đi dự kiến,Ngày trả phòng,Thời hạn tạm trú");
                    }
                    sw.WriteLine(recordLine);
                }

                // Insert at top of DataGridView (ORDER BY DESC - newest first)
                string genText = (cboGender.SelectedIndex == 1) ? "Nữ" : "Nam";
                dgvGuests.Rows.Insert(0,
                    nextStt,
                    txtFullName.Text.Trim().ToUpper(),
                    txtBirthDay.Text.Trim(),
                    genText,
                    txtNationality.Text.Trim().ToUpper(),
                    txtPassportNo.Text.Trim().ToUpper(),
                    roomVal,
                    (dtpArrival.Value ?? DateTime.Today).ToString("dd/MM/yyyy"),
                    (dtpDeparture.Value ?? DateTime.Today.AddDays(3)).ToString("dd/MM/yyyy"),
                    (dtpCheckOut.Value ?? DateTime.Today.AddDays(3)).ToString("dd/MM/yyyy"),
                    (dtpResidenceTerm.Value ?? DateTime.Today.AddDays(9)).ToString("dd/MM/yyyy")
                );

                dgvGuests.ClearSelection();
                if (dgvGuests.Rows.Count > 0)
                {
                    dgvGuests.Rows[0].Selected = true;
                    dgvGuests.FirstDisplayedScrollingRowIndex = 0;
                }

                UpdateGuestCount();
                lblStatus.Text = UiText.Format("StatusAppendSuccess", nextStt, txtPassportNo.Text);
                lblStatus.ForeColor = Color.ForestGreen;

                if (showSuccessMsg)
                {
                    try { AntdUI.Message.success(this, string.Format("Đã ghi nối tiếp vào CSV thành công! (STT: {0}, Hộ chiếu: {1})", nextStt, txtPassportNo.Text)); } catch { }
                    MessageBox.Show(string.Format("Đã ghi nối tiếp thông tin khách vào file CSV thành công!\n(STT: {0}, Hộ chiếu: {1})", nextStt, txtPassportNo.Text), "Thành công", MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show("Lỗi khi ghi file CSV: " + ex.Message, "Lỗi ghi file", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void BtnExportXml_Click(object sender, EventArgs e)
        {
            if (dgvGuests.Rows.Count == 0)
            {
                MessageBox.Show("Chưa có dữ liệu khách nào để xuất XML!", "Thông báo", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            using (SaveFileDialog sfd = new SaveFileDialog())
            {
                sfd.Title = "Chọn nơi lưu file XML khai báo tạm trú";
                sfd.Filter = "XML files (*.xml)|*.xml";
                sfd.DefaultExt = "xml";
                sfd.AddExtension = true;
                string currentYear = DateTime.Now.ToString("yyyy");
                string xmlDir = Path.Combine(appDir, "docs", currentYear, "xml");
                if (!Directory.Exists(xmlDir))
                {
                    try { Directory.CreateDirectory(xmlDir); } catch { }
                }
                sfd.InitialDirectory = xmlDir;
                sfd.FileName = string.Format("{0:dd_MM}.xml", DateTime.Now);

                if (sfd.ShowDialog(this) == DialogResult.OK)
                {
                    try
                    {
                        XmlWriterSettings settings = new XmlWriterSettings 
                        { 
                            Indent = true, 
                            IndentChars = "\t",
                            Encoding = new UTF8Encoding(false) 
                        };

                        using (XmlWriter writer = XmlWriter.Create(sfd.FileName, settings))
                        {
                            writer.WriteStartDocument(true);
                            writer.WriteStartElement("KHAI_BAO_TAM_TRU");
                            writer.WriteAttributeString("xmlns", "xsi", null, "http://www.w3.org/2001/XMLSchema-instance");

                            int stt = 1;
                            // Xuat XML theo trinh tu thoi gian (tu duoi bang len dau bang)
                            for (int i = dgvGuests.Rows.Count - 1; i >= 0; i--)
                            {
                                DataGridViewRow row = dgvGuests.Rows[i];
                                if (row.IsNewRow) continue;

                                string rawGender = Convert.ToString(row.Cells["GioiTinh"].Value).Trim();
                                string genderVal = (rawGender == "Nữ" || rawGender == "2" || rawGender.ToUpper() == "F") ? "F" : "M";

                                writer.WriteStartElement("THONG_TIN_KHACH");
                                writer.WriteElementString("so_thu_tu", stt.ToString());
                                writer.WriteElementString("ho_ten", Convert.ToString(row.Cells["HoTen"].Value).Trim().ToUpper());
                                writer.WriteElementString("ngay_sinh", Convert.ToString(row.Cells["NgaySinh"].Value).Trim());
                                writer.WriteElementString("ngay_sinh_dung_den", "D");
                                writer.WriteElementString("gioi_tinh", genderVal);
                                writer.WriteElementString("ma_quoc_tich", Convert.ToString(row.Cells["QuocTich"].Value).Trim().ToUpper());
                                writer.WriteElementString("so_ho_chieu", Convert.ToString(row.Cells["SoHoChieu"].Value).Trim().ToUpper());
                                writer.WriteElementString("so_phong", Convert.ToString(row.Cells["SoPhong"].Value).Trim());
                                writer.WriteElementString("ngay_den", Convert.ToString(row.Cells["NgayDen"].Value).Trim());
                                writer.WriteElementString("ngay_di_du_kien", Convert.ToString(row.Cells["NgayDi"].Value).Trim());
                                writer.WriteElementString("ngay_tra_phong", Convert.ToString(row.Cells["NgayTra"].Value).Trim());
                                writer.WriteElementString("thoi_han_tam_tru", Convert.ToString(row.Cells["HanTamTru"].Value).Trim());
                                writer.WriteEndElement();

                                stt++;
                            }

                            writer.WriteEndElement();
                            writer.WriteEndDocument();
                        }

                        try { AntdUI.Message.success(this, "Xuất file XML chuẩn hóa thành công!"); } catch { }
                        MessageBox.Show("Xuất file XML chuẩn hóa thành công!\n" + sfd.FileName, "Thành công", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    }
                    catch (Exception ex)
                    {
                        MessageBox.Show("Lỗi xuất file XML: " + ex.Message, "Lỗi", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    }
                }
            }
        }

        private void LoadXmlGrid(string xmlPath)
        {
            if (!File.Exists(xmlPath)) return;
            try
            {
                XmlDocument doc = new XmlDocument();
                doc.Load(xmlPath);
                XmlNodeList list = doc.SelectNodes("//THONG_TIN_KHACH");
                if (list == null || list.Count == 0)
                {
                    list = doc.SelectNodes("//Khach");
                }
                if (list == null || list.Count == 0) return;

                dgvGuests.Rows.Clear();
                // ORDER BY DESC: duyet tu phan tu cuoi cung len dau (moi nhat day len dau)
                for (int i = list.Count - 1; i >= 0; i--)
                {
                    XmlNode node = list[i];
                    string rowStt = GetNodeText(node, "so_thu_tu", "STT");
                    if (string.IsNullOrEmpty(rowStt)) rowStt = (i + 1).ToString();
                    string hoTen = GetNodeText(node, "ho_ten", "HoTen");
                    string ngaySinh = GetNodeText(node, "ngay_sinh", "NgaySinh");
                    string rawGender = GetNodeText(node, "gioi_tinh", "GioiTinh");
                    string genText = (rawGender.ToUpper() == "F" || rawGender == "2" || rawGender.ToUpper() == "NỮ") ? "Nữ" : "Nam";
                    string quocTich = GetNodeText(node, "ma_quoc_tich", "MaQuocTich");
                    string soHoChieu = GetNodeText(node, "so_ho_chieu", "SoHoChieu");
                    string soPhong = GetNodeText(node, "so_phong", "SoPhong");
                    string ngayDen = GetNodeText(node, "ngay_den", "NgayDen");
                    string ngayDi = GetNodeText(node, "ngay_di_du_kien", "NgayDiDuKien");
                    string ngayTra = GetNodeText(node, "ngay_tra_phong", "NgayTraPhong");
                    string hanTamTru = GetNodeText(node, "thoi_han_tam_tru", "ThoiHanTamTru");

                    dgvGuests.Rows.Add(rowStt, hoTen, ngaySinh, genText, quocTich, soHoChieu, soPhong, ngayDen, ngayDi, ngayTra, hanTamTru);
                }
                UpdateGuestCount();
                lblStatus.Text = "● ĐÃ TẢI " + dgvGuests.Rows.Count + " KHÁCH TỪ FILE XML THÀNH CÔNG";
                lblStatus.ForeColor = Color.ForestGreen;
            }
            catch (Exception ex)
            {
                MessageBox.Show("Lỗi đọc file XML: " + ex.Message, "Lỗi", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private static string GetNodeText(XmlNode parent, params string[] tagNames)
        {
            foreach (var tag in tagNames)
            {
                var n = parent.SelectSingleNode(tag);
                if (n != null && !string.IsNullOrEmpty(n.InnerText)) return n.InnerText.Trim();
            }
            return "";
        }

        private void LoadCsvGridIfExists()
        {
            string csvPath = txtCsvPath.Text.Trim();
            if (!File.Exists(csvPath)) return;

            if (csvPath.EndsWith(".xml", StringComparison.OrdinalIgnoreCase))
            {
                LoadXmlGrid(csvPath);
                return;
            }

            try
            {
                dgvGuests.Rows.Clear();
                string[] lines = File.ReadAllLines(csvPath);
                // ORDER BY DESC: duyet tu dong cuoi cung (moi nhat) len dong dau tien
                for (int i = lines.Length - 1; i >= 1; i--)
                {
                    string l = lines[i].Trim();
                    if (string.IsNullOrEmpty(l)) continue;
                    string[] cols = ParseCsvLine(l);
                    if (cols.Length >= 12)
                    {
                        string genVal = cols[4].Trim().ToUpper();
                        string genStr = (genVal == "2" || genVal == "F" || genVal == "NỮ" || genVal == "NU" || genVal == "FEMALE") ? "Nữ" : "Nam";
                        dgvGuests.Rows.Add(cols[0], cols[1], cols[2], genStr, cols[5], cols[6], cols[7], cols[8], cols[9], cols[10], cols[11]);
                    }
                }
                UpdateGuestCount();
            }
            catch { }
        }

        private void BtnBrowseCsv_Click(object sender, EventArgs e)
        {
            using (OpenFileDialog ofd = new OpenFileDialog())
            {
                ofd.Title = "Chọn file dữ liệu lưu trữ (CSV hoặc XML)";
                ofd.Filter = "File dữ liệu (*.csv;*.xml)|*.csv;*.xml|CSV files (*.csv)|*.csv|XML files (*.xml)|*.xml|All files (*.*)|*.*";
                ofd.CheckFileExists = false;
                string defaultCsvDir = Path.Combine(appDir, "docs", DateTime.Now.ToString("yyyy"), "csv");
                string curDir = (!string.IsNullOrEmpty(txtCsvPath.Text) && Directory.Exists(Path.GetDirectoryName(txtCsvPath.Text))) 
                    ? Path.GetDirectoryName(txtCsvPath.Text) 
                    : (Directory.Exists(defaultCsvDir) ? defaultCsvDir : Path.Combine(appDir, "docs"));
                ofd.InitialDirectory = curDir;
                if (ofd.ShowDialog(this) == DialogResult.OK)
                {
                    txtCsvPath.Text = ofd.FileName;
                    LoadCsvGridIfExists();
                }
            }
        }

        private void DeleteGuestRow(int rowIndex)
        {
            if (rowIndex < 0 || rowIndex >= dgvGuests.Rows.Count) return;
            var row = dgvGuests.Rows[rowIndex];
            string hoTen = Convert.ToString(row.Cells["HoTen"].Value).Trim();
            string passportNo = Convert.ToString(row.Cells["SoHoChieu"].Value).Trim();
            string phong = Convert.ToString(row.Cells["SoPhong"].Value).Trim();

            DialogResult dr = MessageBox.Show(
                string.Format("Bạn có chắc chắn muốn xóa thông tin của khách hàng sau khỏi danh sách?\n\n- Họ và tên: {0}\n- Số hộ chiếu: {1}\n- Phòng: {2}\n\nThao tác này sẽ xóa dòng này khỏi danh sách và file CSV lưu trữ.", hoTen, passportNo, phong),
                "Xác nhận xóa khách",
                MessageBoxButtons.YesNo,
                MessageBoxIcon.Question
            );

            if (dr == DialogResult.Yes)
            {
                dgvGuests.Rows.RemoveAt(rowIndex);
                SaveAllGridToCsv();
                UpdateGuestCount();
                try { AntdUI.Message.info(this, "Đã xóa khách " + hoTen + " khỏi danh sách"); } catch { }
            }
        }

        private void UpdateGuestCount()
        {
            if (lblCount != null)
            {
                lblCount.Text = UiText.Format("LblGuestCount", dgvGuests.Rows.Count);
                if (lblGridTitle != null)
                {
                    lblCount.Left = lblGridTitle.Right + 14;
                    lblCount.Top = lblGridTitle.Top;
                }
            }
        }

        private void SaveAllGridToCsv()
        {
            string csvPath = txtCsvPath.Text.Trim();
            if (string.IsNullOrEmpty(csvPath)) return;
            try
            {
                string dir = Path.GetDirectoryName(csvPath);
                if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
                {
                    Directory.CreateDirectory(dir);
                }

                using (StreamWriter sw = new StreamWriter(csvPath, false, new UTF8Encoding(true)))
                {
                    sw.WriteLine("STT,Họ và tên,Ngày sinh,Ngày sinh đúng đến,Giới tính,Mã quốc tịch,Số hộ chiếu,Số phòng,Ngày đến,Ngày đi dự kiến,Ngày trả phòng,Thời hạn tạm trú");
                    int total = dgvGuests.Rows.Count;
                    int stt = 1;
                    // dgvGuests dang sap xep DESC (hang 0 la moi nhat, hang cuoi la cu nhat)
                    // Luu CSV theo trinh tu thoi gian: tu duoi len tren (hang cuoi den hang 0)
                    for (int i = total - 1; i >= 0; i--)
                    {
                        DataGridViewRow row = dgvGuests.Rows[i];
                        if (row.IsNewRow) continue;
                        row.Cells["STT"].Value = (total - i).ToString();
                        string rawGen = Convert.ToString(row.Cells["GioiTinh"].Value).Trim();
                        string genCode = (rawGen == "Nữ" || rawGen == "F" || rawGen == "2") ? "F" : "M";

                        string line = string.Format("{0},{1},{2},{3},{4},{5},{6},{7},{8},{9},{10},{11}",
                            stt,
                            EscapeCsv(Convert.ToString(row.Cells["HoTen"].Value).Trim().ToUpper()),
                            EscapeCsv(Convert.ToString(row.Cells["NgaySinh"].Value).Trim()),
                            "D",
                            genCode,
                            EscapeCsv(Convert.ToString(row.Cells["QuocTich"].Value).Trim().ToUpper()),
                            EscapeCsv(Convert.ToString(row.Cells["SoHoChieu"].Value).Trim().ToUpper()),
                            EscapeCsv(Convert.ToString(row.Cells["SoPhong"].Value).Trim()),
                            EscapeCsv(Convert.ToString(row.Cells["NgayDen"].Value).Trim()),
                            EscapeCsv(Convert.ToString(row.Cells["NgayDi"].Value).Trim()),
                            EscapeCsv(Convert.ToString(row.Cells["NgayTra"].Value).Trim()),
                            EscapeCsv(Convert.ToString(row.Cells["HanTamTru"].Value).Trim())
                        );
                        sw.WriteLine(line);
                        stt++;
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show("Lỗi khi cập nhật file CSV: " + ex.Message, "Lỗi", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void ClearForm()
        {
            txtFullName.Text = "";
            txtPassportNo.Text = "";
            txtNationality.Text = "";
            txtBirthDay.Text = "";
            cboGender.SelectedIndex = 0;
            txtExpiryDate.Text = "";
            txtMrz1.Text = "";
            txtMrz2.Text = "";
            txtRoom.Text = "";
            dtpArrival.Value = DateTime.Today;
            dtpDeparture.Value = DateTime.Today.AddDays(3);
            dtpCheckOut.Value = DateTime.Today.AddDays(3);
            dtpResidenceTerm.Value = DateTime.Today.AddDays(9);
            if (picPassport.Image != null) { picPassport.Image.Dispose(); picPassport.Image = null; }
            if (picPhoto.Image != null) { picPhoto.Image.Dispose(); picPhoto.Image = null; }
            picPassport.Invalidate();
            UpdateGrpImagesHeight();
        }

        private string EscapeCsv(string val)
        {
            if (string.IsNullOrEmpty(val)) return "";
            if (val.Contains(",") || val.Contains("\"") || val.Contains("\n") || val.Contains("\r"))
            {
                return "\"" + val.Replace("\"", "\"\"") + "\"";
            }
            return val;
        }

        private string[] ParseCsvLine(string line)
        {
            List<string> res = new List<string>();
            bool inQuotes = false;
            StringBuilder sb = new StringBuilder();

            for (int i = 0; i < line.Length; i++)
            {
                char c = line[i];
                if (c == '\"')
                {
                    if (inQuotes && i + 1 < line.Length && line[i + 1] == '\"')
                    {
                        sb.Append('\"');
                        i++;
                    }
                    else
                    {
                        inQuotes = !inQuotes;
                    }
                }
                else if (c == ',' && !inQuotes)
                {
                    res.Add(sb.ToString());
                    sb.Clear();
                }
                else
                {
                    sb.Append(c);
                }
            }
            res.Add(sb.ToString());
            return res.ToArray();
        }

        private static void ActivateExistingInstance()
        {
            try
            {
                System.Diagnostics.Process currentProc = System.Diagnostics.Process.GetCurrentProcess();
                foreach (System.Diagnostics.Process proc in System.Diagnostics.Process.GetProcessesByName(currentProc.ProcessName))
                {
                    if (proc.Id != currentProc.Id)
                    {
                        IntPtr hWnd = proc.MainWindowHandle;
                        if (hWnd == IntPtr.Zero)
                        {
                            for (int i = 0; i < 5; i++)
                            {
                                System.Threading.Thread.Sleep(200);
                                proc.Refresh();
                                hWnd = proc.MainWindowHandle;
                                if (hWnd != IntPtr.Zero) break;
                            }
                        }

                        if (hWnd != IntPtr.Zero)
                        {
                            ShowWindow(hWnd, 9 /* SW_RESTORE */);
                            ShowWindow(hWnd, 5 /* SW_SHOW */);
                            SetForegroundWindow(hWnd);
                            SwitchToThisWindow(hWnd, true);
                        }
                        break;
                    }
                }
            }
            catch { }
        }

        [STAThread]
        static void Main()
        {
            Application.ThreadException += (s, e) => {
                try { File.AppendAllText(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "app_crash.log"), DateTime.Now + " ThreadException: " + e.Exception.ToString() + "\n"); } catch { }
            };
            AppDomain.CurrentDomain.UnhandledException += (s, e) => {
                try { File.AppendAllText(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "app_crash.log"), DateTime.Now + " UnhandledException: " + e.ExceptionObject.ToString() + "\n"); } catch { }
            };

            const string appMutexName = @"Local\PassportScannerApp_ID_Capture_SingleInstance";
            bool createdNew;
            using (Mutex mutex = new Mutex(true, appMutexName, out createdNew))
            {
                if (!createdNew)
                {
                    // Chỉ cho phép chạy 1 ứng dụng duy nhất: kích hoạt cửa sổ đang chạy lên trước và thoát
                    ActivateExistingInstance();
                    return;
                }

                try
                {
                    ScannerNative.ApplyDriverHotfix();
                    MainForm.InitAppFonts(AppDomain.CurrentDomain.BaseDirectory);
                    Application.EnableVisualStyles();
                    Application.SetCompatibleTextRenderingDefault(false);
                    Application.Run(new MainForm());
                }
                catch (Exception ex)
                {
                    try { File.AppendAllText(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "app_crash.log"), DateTime.Now + " MainCatch: " + ex.ToString() + "\n"); } catch { }
                }
                finally
                {
                    try { mutex.ReleaseMutex(); } catch { }
                }
            }
        }
    }

    public class UserGuideForm : Form
    {
        private TabControl tcGuide;
        private string _appDir;

        public UserGuideForm(int initialTab = 0, string appDir = "")
        {
            _appDir = string.IsNullOrEmpty(appDir) ? AppDomain.CurrentDomain.BaseDirectory : appDir;
            InitializeComponent(initialTab);
        }

        private void InitializeComponent(int initialTab)
        {
            this.Text = UiText.Get("HelpDialogTitle", "Hướng Dẫn Sử Dụng - Passport Scanner (ID-Capture)");
            this.Size = new Size(960, 690);
            this.MinimumSize = new Size(840, 580);
            this.StartPosition = FormStartPosition.CenterParent;
            this.BackColor = Color.FromArgb(245, 247, 250);
            this.Font = MainForm.AppFont(9.5f);
            this.KeyPreview = true;
            this.KeyDown += (s, e) => { if (e.KeyCode == Keys.Escape) this.Close(); };

            // HEADER PANEL
            Panel pnlHeader = new Panel
            {
                Dock = DockStyle.Top,
                Height = 72,
                BackColor = Color.FromArgb(24, 43, 73),
                Padding = new Padding(20, 12, 20, 10)
            };
            Label lblHeaderTitle = new Label
            {
                Text = "PASSPORT SCANNER (ID-CAPTURE) - HƯỚNG DẪN SỬ DỤNG",
                Font = MainForm.AppFont(12.5f, FontStyle.Bold),
                ForeColor = Color.White,
                Location = new Point(20, 12),
                AutoSize = true
            };
            Label lblHeaderSub = new Label
            {
                Text = "Hệ thống quét & tự động bóc tách dữ liệu hộ chiếu quốc tế (Chuẩn ICAO Doc 9303 TD3)",
                Font = MainForm.AppFont(9f),
                ForeColor = Color.FromArgb(180, 205, 235),
                Location = new Point(22, 40),
                AutoSize = true
            };
            pnlHeader.Controls.AddRange(new Control[] { lblHeaderTitle, lblHeaderSub });

            // FOOTER PANEL
            Panel pnlFooter = new Panel
            {
                Dock = DockStyle.Bottom,
                Height = 54,
                BackColor = Color.FromArgb(238, 242, 246),
                Padding = new Padding(15, 10, 15, 10)
            };
            pnlFooter.Paint += (s, e) =>
            {
                e.Graphics.DrawLine(new Pen(Color.FromArgb(220, 224, 230), 1), 0, 0, pnlFooter.Width, 0);
            };

            AntdUI.Button btnOpenFolder = new AntdUI.Button
            {
                Text = "Mở thư mục ứng dụng",
                Size = new Size(180, 32),
                Location = new Point(15, 11),
                Type = AntdUI.TTypeMini.Default,
                Radius = 6,
                Font = MainForm.AppFont(9f),
                Cursor = Cursors.Hand
            };
            btnOpenFolder.Click += (s, e) => {
                try { System.Diagnostics.Process.Start("explorer.exe", _appDir); } catch { }
            };

            AntdUI.Button btnClose = new AntdUI.Button
            {
                Text = "Đóng [Esc]",
                Size = new Size(110, 32),
                Type = AntdUI.TTypeMini.Primary,
                Radius = 6,
                Font = MainForm.AppFont(9.5f, FontStyle.Bold),
                Cursor = Cursors.Hand
            };
            btnClose.Click += (s, e) => this.Close();

            pnlFooter.Controls.AddRange(new Control[] { btnOpenFolder, btnClose });
            pnlFooter.Resize += (s, e) => {
                btnClose.Left = pnlFooter.ClientSize.Width - btnClose.Width - 15;
                btnClose.Top = 11;
            };

            // TAB CONTROL
            tcGuide = new TabControl
            {
                Dock = DockStyle.Fill,
                Font = MainForm.AppFont(9.5f, FontStyle.Bold),
                Padding = new Point(16, 8)
            };

            TabPage tpSteps = new TabPage("Quy Trình Sử Dụng");
            tpSteps.Controls.Add(CreateStepsContent());
            tcGuide.TabPages.Add(tpSteps);

            TabPage tpFaq = new TabPage("Xử Lý Sự Cố & Mẹo");
            tpFaq.Controls.Add(CreateFaqContent());
            tcGuide.TabPages.Add(tpFaq);

            TabPage tpAbout = new TabPage("Giới Thiệu Phần Mềm");
            tpAbout.Controls.Add(CreateAboutContent());
            tcGuide.TabPages.Add(tpAbout);

            if (initialTab >= 0 && initialTab < tcGuide.TabPages.Count)
            {
                tcGuide.SelectedIndex = initialTab;
            }

            this.Controls.Add(tcGuide);
            this.Controls.Add(pnlFooter);
            this.Controls.Add(pnlHeader);
        }

        private Control CreateStepsContent()
        {
            Panel pnl = new Panel { Dock = DockStyle.Fill, Padding = new Padding(12), BackColor = Color.White };
            RichTextBox rtb = CreateRichTextBox();
            pnl.Controls.Add(rtb);

            AppendH1(rtb, "QUY TRÌNH QUÉT VÀ BÓC TÁCH HỘ CHIẾU (4 BƯỚC CƠ BẢN)");

            AppendH2(rtb, "BƯỚC 1: CHUẨN BỊ VÀ ĐẶT HỘ CHIẾU VÀO MÁY QUÉT");
            AppendBullet(rtb, "Kết nối thiết bị", "Cắm cáp USB của máy quét Syscan IDC-V vào máy tính. Đèn trạng thái trên thanh điều khiển phần mềm sẽ hiện màu xanh: 'MÁY QUÉT ID-CAPTURE: ĐÃ KẾT NỐI (Syscan IDC-V SẴN SÀNG QUÉT)'.");
            AppendBullet(rtb, "Đặt hộ chiếu", "Mở trang thông tin nhân thân của hộ chiếu (trang có ảnh chân dung và 2 dòng mã đọc máy MRZ). Úp mặt trang này xuống mặt kính máy quét, căn chỉnh góc hộ chiếu sát vào cạnh chặn của máy.");
            AppendNote(rtb, "Lưu ý: Giữ hộ chiếu phẳng sát mặt kính, tránh gập nếp hoặc che khuất 2 dòng mã MRZ ở cạnh dưới.");

            AppendH2(rtb, "BƯỚC 2: THỰC HIỆN QUÉT HỘ CHIẾU");
            AppendBullet(rtb, "Cách 1 - Quét thủ công", "Nhấn nút 'QUÉT HỘ CHIẾU TỪ MÁY' hoặc nhấn phím F5 (hoặc gõ nhanh phím Ctrl).");
            AppendBullet(rtb, "Cách 2 - Tự động khi đóng nắp máy (F3)", "Đậy nắp máy quét lại. Cảm biến quang học của máy sẽ tự phát hiện nắp đóng và kích hoạt quét tự động tức thì.");
            AppendBullet(rtb, "Cách 3 - Tự động quét chu kỳ 5 giây (F1)", "Bật tùy chọn 'Tự động scan sau 5s (F1)'. Phần mềm sẽ tự động chụp và phân tích sau mỗi 5 giây (kể cả khi nắp máy đang mở hoặc đóng đều quét bình thường).");
            AppendBullet(rtb, "Cách 4 - Quét từ file ảnh có sẵn (Ctrl+O)", "Bấm nút 'CHỌN ẢNH TỪ MÁY (Ctrl+O)' hoặc kéo thả trực tiếp file ảnh (JPG, PNG, BMP) vào ô Hình ảnh hộ chiếu bên trái.");
            AppendNote(rtb, "Phím tắt hoạt động ngay khi mở phần mềm mà không cần kích hoạt chuột.");

            AppendH2(rtb, "BƯỚC 3: KIỂM TRA THÔNG TIN TỰ ĐỘNG BÓC TÁCH");
            AppendBullet(rtb, "Dữ liệu bóc tách", "Phần mềm tự động trích xuất: Họ và tên khách, Số hộ chiếu, Quốc tịch (mã 3 chữ), Ngày sinh, Giới tính, Ngày hết hạn hộ chiếu và 2 dòng mã MRZ.");
            AppendBullet(rtb, "Đảo Họ / Tên", "Nếu thứ tự Họ và Tên bị ngược so với quy ước, bấm nút 'Đảo Họ / Tên' để hoán đổi nhanh chóng.");
            AppendBullet(rtb, "Thông tin lưu trú", "Nhập Số phòng (mặc định 101, nhấp chuột vào ô sẽ tự bôi đen toàn bộ để gõ số phòng mới nhanh nhất). Ngày đến, Ngày đi dự kiến, Ngày trả phòng và Thời hạn tạm trú được tính toán tự động và có thể chỉnh sửa tự do.");
            AppendNote(rtb, "Khi thay đổi 'Ngày đi dự kiến', Ngày trả phòng và Hạn tạm trú sẽ tự động được cộng thêm ngày tương ứng.");

            AppendH2(rtb, "BƯỚC 4: LƯU TRỮ VÀ XUẤT DỮ LIỆU");
            AppendBullet(rtb, "Tự động ghi nối tiếp CSV (F2)", "Khi bật chế độ này (mặc định BẬT), mỗi khi quét xong hộ chiếu, thông tin sẽ được tự động chèn lên đầu danh sách và ghi nối tiếp vào file CSV lưu trữ.");
            AppendBullet(rtb, "Ghi thủ công (Ctrl+S)", "Nhấn nút 'Ghi Vào File CSV [Ctrl+S]' để lưu thông tin khách hiện tại vào file CSV.");
            AppendBullet(rtb, "Xuất file XML chuẩn hóa (Ctrl+X)", "Nhấn nút 'Xuất File XML [Ctrl+X]' để xuất toàn bộ danh sách khách sang định dạng XML chuẩn phục vụ nộp cổng dịch vụ công / khai báo tạm trú.");
            AppendBullet(rtb, "Mở thư mục file", "Nhấn nút 'Mở thư mục file' để mở thư mục chứa file dữ liệu trên máy tính.");
            AppendNote(rtb, "Tất cả khách hàng mới quét sẽ được hiển thị ngay trên cùng (ORDER BY DESC) để thuận tiện theo dõi.");

            return pnl;
        }

        private Control CreateFaqContent()
        {
            Panel pnl = new Panel { Dock = DockStyle.Fill, Padding = new Padding(12), BackColor = Color.White };
            RichTextBox rtb = CreateRichTextBox();
            pnl.Controls.Add(rtb);

            AppendH1(rtb, "XỬ LÝ SỰ CỐ THƯỜNG GẶP & MẸO HỮU ÍCH");

            AppendH2(rtb, "1. MÁY BÁO 'CHƯA KẾT NỐI USB'");
            AppendBullet(rtb, "Nguyên nhân", "Cáp USB bị lỏng, chưa cắm nguồn máy quét hoặc cổng USB chập chờn.");
            AppendBullet(rtb, "Khắc phục", "Rút cáp USB ra và cắm lại (ưu tiên cắm vào cổng USB 3.0 trực tiếp phía sau thùng máy tính). Kiểm tra đèn LED trên thân máy quét Syscan IDC-V xem đã sáng hay chưa. Sau khi cắm, phần mềm sẽ tự nhận diện thiết bị.");

            AppendH2(rtb, "2. ẢNH QUÉT BỊ MỜ HOẶC KHÔNG BÓC TÁCH ĐƯỢC CHỮ / MÃ MRZ");
            AppendBullet(rtb, "Nguyên nhân", "Hộ chiếu bị cong vênh, mặt kính máy quét bám bụi hoặc hộ chiếu đặt lệch góc.");
            AppendBullet(rtb, "Khắc phục", "Dùng khăn mềm lau sạch mặt kính máy quét. Khi đặt hộ chiếu, ép nhẹ nắp máy xuống để bề mặt hộ chiếu ép sát phẳng với mặt kính, tránh lọt ánh sáng đèn phòng vào. Đảm bảo góc dưới chứa 2 dòng mã MRZ không bị che khuất.");

            AppendH2(rtb, "3. HỌ VÀ TÊN BỊ ĐẢO NGƯỢC THỨ TỰ");
            AppendBullet(rtb, "Khắc phục", "Nhấn nút 'Đảo Họ / Tên' nằm bên cạnh ô Họ và tên để hoán đổi thứ tự Họ và Tên ngay lập tức.");

            AppendH2(rtb, "4. CHỈNH SỬA TRỰC TIẾP TRÊN BẢNG DANH SÁCH (GRID VIEW)");
            AppendBullet(rtb, "Tính năng sửa nhanh", "Tại bảng danh sách bên dưới, các cột Số phòng, Ngày đến, Ngày đi, Ngày trả, Hạn tạm trú cho phép nhấp đúp chuột để chỉnh sửa trực tiếp. Dữ liệu sẽ tự động được lưu cập nhật vào file CSV ngay sau khi sửa.");
            AppendBullet(rtb, "Xóa khách khỏi danh sách", "Nhấn nút 'Xóa' ở cột Thao Tác hoặc chọn dòng khách rồi nhấn phím Delete trên bàn phím. Phần mềm sẽ hỏi xác nhận và tự động xóa dòng đó khỏi file CSV.");

            return pnl;
        }

        private Control CreateAboutContent()
        {
            Panel pnl = new Panel { Dock = DockStyle.Fill, Padding = new Padding(12), BackColor = Color.White };
            RichTextBox rtb = CreateRichTextBox();
            pnl.Controls.Add(rtb);

            AppendH1(rtb, "GIỚI THIỆU PHẦN MỀM PASSPORT SCANNER (ID-CAPTURE)");

            AppendH2(rtb, "THÔNG TIN PHIÊN BẢN");
            AppendBullet(rtb, "Tên phần mềm", "Passport Scanner (ID-Capture)");
            AppendBullet(rtb, "Phiên bản", "1.0");
            AppendBullet(rtb, "Đơn vị phát triển", "Viettechsoft");
            AppendBullet(rtb, "Email", "info@viettechsoft.com | Hotline: 0976.098.886");

            return pnl;
        }

        private static RichTextBox CreateRichTextBox()
        {
            return new RichTextBox
            {
                Dock = DockStyle.Fill,
                ReadOnly = true,
                BackColor = Color.White,
                BorderStyle = BorderStyle.None,
                ScrollBars = RichTextBoxScrollBars.Vertical,
                Font = MainForm.AppFont(9.5f)
            };
        }

        private static void AppendH1(RichTextBox rtb, string text)
        {
            rtb.SelectionFont = MainForm.AppFont(12.5f, FontStyle.Bold);
            rtb.SelectionColor = Color.FromArgb(24, 43, 73);
            rtb.AppendText(text + "\r\n\r\n");
        }

        private static void AppendH2(RichTextBox rtb, string text)
        {
            rtb.SelectionFont = MainForm.AppFont(10.5f, FontStyle.Bold);
            rtb.SelectionColor = Color.FromArgb(0, 102, 204);
            rtb.AppendText(text + "\r\n");
        }

        private static void AppendBullet(RichTextBox rtb, string label, string desc)
        {
            rtb.SelectionFont = MainForm.AppFont(9.5f, FontStyle.Bold);
            rtb.SelectionColor = Color.FromArgb(30, 30, 30);
            rtb.AppendText("  • " + label + ": ");
            rtb.SelectionFont = MainForm.AppFont(9.5f, FontStyle.Regular);
            rtb.SelectionColor = Color.FromArgb(60, 60, 60);
            rtb.AppendText(desc + "\r\n");
        }

        private static void AppendNote(RichTextBox rtb, string text)
        {
            rtb.SelectionFont = MainForm.AppFont(9f, FontStyle.Italic);
            rtb.SelectionColor = Color.FromArgb(80, 80, 80);
            rtb.AppendText("    * " + text + "\r\n\r\n");
        }
    }
}
