using System;
using System.IO;
using System.Text;
using System.Drawing;
using System.Windows.Forms;
using System.Diagnostics;
using System.Threading;
using System.Reflection;
using System.IO.Compression;
using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace ViettechsoftInstaller
{
    public class SetupForm : Form
    {
        [DllImport("shell32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern void SHChangeNotify(int wEventId, int uFlags, IntPtr dwItem1, IntPtr dwItem2);

        private const int SHCNE_ASSOCCHANGED = 0x08000000;
        private const int SHCNF_IDLIST = 0x0000;

        private TextBox txtTargetDir;
        private Button btnBrowse;
        private CheckBox chkDriver;
        private CheckBox chkDesktop;
        private CheckBox chkStartMenu;
        private CheckBox chkLaunch;
        private ProgressBar progressBar;
        private Label lblStatus;
        private Button btnInstall;
        private Button btnCancel;
        private bool isInstalling = false;
        private bool isFinished = false;
        private string detectedExistingPath = null;
        private bool shouldRemoveOldVersion = false;

        public SetupForm()
        {
            InitializeComponent();
            this.Shown += (s, e) => CheckExistingInstallation();
        }

        private void InitializeComponent()
        {
            this.Text = "Cài Đặt Passport Scanner (ID-Capture) - Viettechsoft";
            this.Size = new Size(640, 485);
            this.FormBorderStyle = FormBorderStyle.FixedSingle;
            this.MaximizeBox = false;
            this.MinimizeBox = true;
            this.ShowIcon = true;
            this.StartPosition = FormStartPosition.CenterScreen;
            this.BackColor = Color.FromArgb(248, 250, 252);
            this.Font = new Font("Segoe UI", 9.25f, FontStyle.Regular);

            // 1. Tải icon từ Embedded Resource hoặc file app.ico
            Icon appIcon = null;
            Image appLogoBmp = null;
            try
            {
                using (Stream stream = Assembly.GetExecutingAssembly().GetManifestResourceStream("app.ico"))
                {
                    if (stream != null)
                    {
                        byte[] icoBytes = new byte[stream.Length];
                        stream.Read(icoBytes, 0, icoBytes.Length);
                        using (MemoryStream ms = new MemoryStream(icoBytes))
                        {
                            appIcon = new Icon(ms);
                        }
                        using (MemoryStream ms2 = new MemoryStream(icoBytes))
                        {
                            using (Icon ico48 = new Icon(ms2, 48, 48))
                            {
                                appLogoBmp = ico48.ToBitmap();
                            }
                        }
                    }
                }
            }
            catch { }

            if (appIcon == null && File.Exists("app.ico"))
            {
                try
                {
                    appIcon = new Icon("app.ico");
                    using (Icon ico48 = new Icon("app.ico", 48, 48))
                    {
                        appLogoBmp = ico48.ToBitmap();
                    }
                }
                catch { }
            }

            if (appIcon != null)
            {
                this.Icon = appIcon;
            }

            // TOP BANNER
            Panel pnlHeader = new Panel
            {
                Dock = DockStyle.Top,
                Height = 84,
                BackColor = Color.FromArgb(24, 43, 73)
            };

            PictureBox picHeaderLogo = new PictureBox
            {
                Location = new Point(18, 14),
                Size = new Size(56, 56),
                SizeMode = PictureBoxSizeMode.Zoom,
                BackColor = Color.Transparent
            };
            // Ưu tiên lấy icon.png độ nét cao làm Logo Header
            try
            {
                using (Stream stream = Assembly.GetExecutingAssembly().GetManifestResourceStream("icon.png"))
                {
                    if (stream != null) picHeaderLogo.Image = Image.FromStream(stream);
                }
            }
            catch { }

            if (picHeaderLogo.Image == null && File.Exists("icon.png"))
            {
                try { picHeaderLogo.Image = Image.FromFile("icon.png"); } catch { }
            }
            if (picHeaderLogo.Image == null && appLogoBmp != null)
            {
                picHeaderLogo.Image = appLogoBmp;
            }
            else if (picHeaderLogo.Image == null && appIcon != null)
            {
                picHeaderLogo.Image = appIcon.ToBitmap();
            }

            Label lblHeaderTitle = new Label
            {
                Text = "CÀI ĐẶT PASSPORT SCANNER (ID-CAPTURE)",
                Font = new Font("Segoe UI", 12.5f, FontStyle.Bold),
                ForeColor = Color.White,
                Location = new Point(86, 16),
                AutoSize = true
            };
            Label lblHeaderSub = new Label
            {
                Text = "Phần mềm bóc tách thông tin hộ chiếu & quản lý lưu trú khách hàng",
                Font = new Font("Segoe UI", 9f, FontStyle.Regular),
                ForeColor = Color.FromArgb(200, 215, 235),
                Location = new Point(88, 46),
                AutoSize = true
            };
            pnlHeader.Controls.AddRange(new Control[] { picHeaderLogo, lblHeaderTitle, lblHeaderSub });
            this.Controls.Add(pnlHeader);

            // BODY
            Panel pnlBody = new Panel
            {
                Location = new Point(0, 84),
                Size = new Size(624, 310),
                BackColor = Color.Transparent,
                Padding = new Padding(24, 18, 24, 10)
            };

            Label lblPathTitle = new Label
            {
                Text = "Thư mục cài đặt phần mềm:",
                Font = new Font("Segoe UI", 9.5f, FontStyle.Bold),
                ForeColor = Color.FromArgb(30, 41, 59),
                Location = new Point(24, 14),
                AutoSize = true
            };

            string defaultDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "Viettechsoft", "ID_Capture");
            txtTargetDir = new TextBox
            {
                Text = defaultDir,
                Location = new Point(24, 38),
                Size = new Size(465, 26),
                Font = new Font("Segoe UI", 9.5f)
            };

            btnBrowse = new Button
            {
                Text = "Duyệt...",
                Location = new Point(498, 36),
                Size = new Size(95, 29),
                Cursor = Cursors.Hand,
                FlatStyle = FlatStyle.System
            };
            btnBrowse.Click += (s, e) =>
            {
                using (FolderBrowserDialog fbd = new FolderBrowserDialog())
                {
                    fbd.Description = "Chọn thư mục cài đặt phần mềm Passport Scanner";
                    fbd.SelectedPath = txtTargetDir.Text;
                    if (fbd.ShowDialog(this) == DialogResult.OK)
                    {
                        txtTargetDir.Text = fbd.SelectedPath;
                    }
                }
            };

            Label lblOptionsTitle = new Label
            {
                Text = "Tùy chọn cài đặt:",
                Font = new Font("Segoe UI", 9.5f, FontStyle.Bold),
                ForeColor = Color.FromArgb(30, 41, 59),
                Location = new Point(24, 82),
                AutoSize = true
            };

            chkDriver = new CheckBox
            {
                Text = "Tự động cài đặt Driver máy quét ID-Capture (Syscan IDC-V USB Driver)",
                Checked = true,
                Location = new Point(26, 108),
                Size = new Size(560, 24),
                Cursor = Cursors.Hand,
                Font = new Font("Segoe UI", 9.25f, FontStyle.Bold),
                ForeColor = Color.FromArgb(0, 102, 204)
            };

            chkDesktop = new CheckBox
            {
                Text = "Tạo biểu tượng lối tắt ngoài màn hình nền (Desktop)",
                Checked = true,
                Location = new Point(26, 136),
                Size = new Size(560, 24),
                Cursor = Cursors.Hand
            };

            chkStartMenu = new CheckBox
            {
                Text = "Tạo lối tắt trong Start Menu (Viettechsoft)",
                Checked = true,
                Location = new Point(26, 164),
                Size = new Size(560, 24),
                Cursor = Cursors.Hand
            };

            chkLaunch = new CheckBox
            {
                Text = "Khởi chạy Passport Scanner ngay sau khi cài đặt hoàn tất",
                Checked = true,
                Location = new Point(26, 192),
                Size = new Size(560, 24),
                Cursor = Cursors.Hand
            };

            lblStatus = new Label
            {
                Text = "Sẵn sàng cài đặt phần mềm lên máy tính.",
                Location = new Point(24, 236),
                Size = new Size(570, 22),
                ForeColor = Color.FromArgb(71, 85, 105),
                Font = new Font("Segoe UI", 9f, FontStyle.Italic)
            };

            progressBar = new ProgressBar
            {
                Location = new Point(24, 260),
                Size = new Size(569, 22),
                Style = ProgressBarStyle.Blocks,
                Value = 0
            };

            pnlBody.Controls.AddRange(new Control[] {
                lblPathTitle, txtTargetDir, btnBrowse,
                lblOptionsTitle, chkDriver, chkDesktop, chkStartMenu, chkLaunch,
                lblStatus, progressBar
            });
            this.Controls.Add(pnlBody);

            // FOOTER
            Panel pnlFooter = new Panel
            {
                Dock = DockStyle.Bottom,
                Height = 60,
                BackColor = Color.FromArgb(241, 245, 249)
            };
            pnlFooter.Paint += (s, e) =>
            {
                e.Graphics.DrawLine(new Pen(Color.FromArgb(226, 232, 240)), 0, 0, pnlFooter.Width, 0);
            };

            btnCancel = new Button
            {
                Text = "Hủy bỏ",
                Location = new Point(498, 14),
                Size = new Size(95, 32),
                Cursor = Cursors.Hand,
                FlatStyle = FlatStyle.System
            };
            btnCancel.Click += (s, e) => this.Close();

            btnInstall = new Button
            {
                Text = "Cài đặt ngay",
                Location = new Point(386, 14),
                Size = new Size(104, 32),
                Cursor = Cursors.Hand,
                Font = new Font("Segoe UI", 9.25f, FontStyle.Bold),
                FlatStyle = FlatStyle.System
            };
            btnInstall.Click += BtnInstall_Click;

            pnlFooter.Controls.AddRange(new Control[] { btnInstall, btnCancel });
            this.Controls.Add(pnlFooter);
        }

        private static string DetectExistingInstallation()
        {
            try
            {
                // 1. Kiểm tra Registry Uninstall
                string[] regPaths = new string[] {
                    @"Software\Microsoft\Windows\CurrentVersion\Uninstall\Viettechsoft_ID_Capture",
                    @"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Viettechsoft_ID_Capture"
                };

                foreach (string regPath in regPaths)
                {
                    using (RegistryKey key = Registry.LocalMachine.OpenSubKey(regPath))
                    {
                        if (key != null)
                        {
                            object loc = key.GetValue("InstallLocation");
                            if (loc != null && !string.IsNullOrEmpty(loc.ToString()) && Directory.Exists(loc.ToString()))
                            {
                                if (File.Exists(Path.Combine(loc.ToString(), "PassportScannerApp.exe")))
                                {
                                    return loc.ToString();
                                }
                            }
                        }
                    }
                }

                // 2. Kiểm tra thư mục mặc định trong Program Files (x86)
                string defaultDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "Viettechsoft", "ID_Capture");
                if (Directory.Exists(defaultDir) && File.Exists(Path.Combine(defaultDir, "PassportScannerApp.exe")))
                {
                    return defaultDir;
                }

                // 3. Kiểm tra Program Files 64-bit (nếu có)
                string prog64 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
                string dir64 = Path.Combine(prog64, "Viettechsoft", "ID_Capture");
                if (Directory.Exists(dir64) && File.Exists(Path.Combine(dir64, "PassportScannerApp.exe")))
                {
                    return dir64;
                }
            }
            catch { }
            return null;
        }

        private void CheckExistingInstallation()
        {
            try
            {
                string existingPath = DetectExistingInstallation();
                if (!string.IsNullOrEmpty(existingPath))
                {
                    detectedExistingPath = existingPath;
                    DialogResult dr = MessageBox.Show(
                        this,
                        string.Format(
                            "Phần mềm Passport Scanner (ID-Capture) đã được cài đặt trước đó tại:\n\"{0}\"\n\n" +
                            "Theo quy định, phần mềm chỉ được cài đặt 1 bản duy nhất trên hệ thống.\n\n" +
                            "Bạn có muốn gỡ bỏ phiên bản cũ để cài đặt lại phiên bản mới không?\n\n" +
                            "• Nhấn [Yes]: Tự động gỡ bỏ phiên bản cũ và tiếp tục cài đặt bản mới.\n" +
                            "• Nhấn [No]: Hủy bỏ và đóng chương trình cài đặt.",
                            existingPath),
                        "Phát hiện phần mềm đã cài đặt",
                        MessageBoxButtons.YesNo,
                        MessageBoxIcon.Question
                    );

                    if (dr != DialogResult.Yes)
                    {
                        this.Close();
                        return;
                    }

                    shouldRemoveOldVersion = true;
                    txtTargetDir.Text = existingPath;
                    lblStatus.Text = "Đã xác nhận gỡ bỏ bản cũ để cài đặt lại.";
                    lblStatus.ForeColor = Color.FromArgb(0, 102, 204);
                }
            }
            catch { }
        }

        private void UninstallOldVersion(string oldDir)
        {
            try
            {
                UpdateStatus("Đang đóng ứng dụng cũ và gỡ bỏ phiên bản trước...", 8);

                // 1. Đóng ứng dụng cũ nếu đang chạy
                foreach (var p in Process.GetProcessesByName("PassportScannerApp"))
                {
                    try { p.Kill(); p.WaitForExit(3000); } catch { }
                }

                // 2. Xóa các shortcut cũ trên Desktop
                string userDesktop = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
                string commonDesktop = Environment.GetFolderPath(Environment.SpecialFolder.CommonDesktopDirectory);
                try { if (!string.IsNullOrEmpty(userDesktop)) File.Delete(Path.Combine(userDesktop, "Passport Scanner (ID-Capture).lnk")); } catch { }
                try { if (!string.IsNullOrEmpty(commonDesktop)) File.Delete(Path.Combine(commonDesktop, "Passport Scanner (ID-Capture).lnk")); } catch { }

                // 3. Xóa các shortcut cũ trong Start Menu
                string userStart = Environment.GetFolderPath(Environment.SpecialFolder.Programs);
                string commonStart = Environment.GetFolderPath(Environment.SpecialFolder.CommonPrograms);
                try { if (!string.IsNullOrEmpty(userStart)) { string d = Path.Combine(userStart, "Viettechsoft"); if (Directory.Exists(d)) Directory.Delete(d, true); } } catch { }
                try { if (!string.IsNullOrEmpty(commonStart)) { string d = Path.Combine(commonStart, "Viettechsoft"); if (Directory.Exists(d)) Directory.Delete(d, true); } } catch { }

                // 4. Xóa Registry gỡ cài đặt cũ
                try
                {
                    Registry.LocalMachine.DeleteSubKeyTree(@"Software\Microsoft\Windows\CurrentVersion\Uninstall\Viettechsoft_ID_Capture", false);
                }
                catch { }
                try
                {
                    Registry.LocalMachine.DeleteSubKeyTree(@"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Viettechsoft_ID_Capture", false);
                }
                catch { }

                // 5. Dọn dẹp các tệp tin nhị phân của phiên bản cũ trong thư mục cài đặt (giữ lại docs và images)
                if (!string.IsNullOrEmpty(oldDir) && Directory.Exists(oldDir))
                {
                    string[] exts = new string[] { "*.exe", "*.dll", "*.bat", "*.manifest" };
                    foreach (string ext in exts)
                    {
                        try
                        {
                            foreach (string f in Directory.GetFiles(oldDir, ext))
                            {
                                try { File.Delete(f); } catch { }
                            }
                        }
                        catch { }
                    }
                }
            }
            catch { }
        }

        private void BtnInstall_Click(object sender, EventArgs e)
        {
            if (isFinished)
            {
                if (chkLaunch.Checked)
                {
                    string target = txtTargetDir.Text.Trim();
                    string exePath = Path.Combine(target, "PassportScannerApp.exe");
                    if (File.Exists(exePath))
                    {
                        try
                        {
                            ProcessStartInfo psi = new ProcessStartInfo(exePath)
                            {
                                WorkingDirectory = target,
                                UseShellExecute = true
                            };
                            Process.Start(psi);
                        }
                        catch { }
                    }
                }
                this.Close();
                return;
            }

            if (isInstalling) return;

            string targetDir = txtTargetDir.Text.Trim();
            if (string.IsNullOrEmpty(targetDir))
            {
                MessageBox.Show("Vui lòng chọn thư mục cài đặt hợp lệ!", "Thông báo", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            // Nếu chưa xác nhận gỡ bỏ phiên bản cũ, kiểm tra xem thư mục này hoặc máy tính đã có cài đặt hay chưa
            if (!shouldRemoveOldVersion)
            {
                string existingExe = Path.Combine(targetDir, "PassportScannerApp.exe");
                string regExisting = DetectExistingInstallation();
                if (File.Exists(existingExe) || !string.IsNullOrEmpty(regExisting))
                {
                    string existLoc = File.Exists(existingExe) ? targetDir : regExisting;
                    DialogResult dr = MessageBox.Show(
                        this,
                        string.Format(
                            "Phần mềm Passport Scanner (ID-Capture) đã tồn tại trên máy tính tại:\n\"{0}\"\n\n" +
                            "Phần mềm chỉ được cài đặt 1 bản duy nhất trên hệ thống.\n\n" +
                            "Bạn có muốn gỡ bỏ phiên bản cũ để cài đặt lại phiên bản mới không?",
                            existLoc),
                        "Xác nhận cài đặt lại",
                        MessageBoxButtons.YesNo,
                        MessageBoxIcon.Warning
                    );

                    if (dr != DialogResult.Yes)
                    {
                        return;
                    }
                    shouldRemoveOldVersion = true;
                    detectedExistingPath = existLoc;
                }
            }

            isInstalling = true;
            btnInstall.Enabled = false;
            btnBrowse.Enabled = false;
            txtTargetDir.ReadOnly = true;
            chkDriver.Enabled = false;
            chkDesktop.Enabled = false;
            chkStartMenu.Enabled = false;
            chkLaunch.Enabled = false;
            btnCancel.Enabled = false;

            Thread t = new Thread(() => DoInstall(targetDir));
            t.IsBackground = true;
            t.Start();
        }

        private void UpdateStatus(string text, int progressVal)
        {
            if (this.InvokeRequired)
            {
                this.BeginInvoke(new Action(() => UpdateStatus(text, progressVal)));
                return;
            }
            lblStatus.Text = text;
            if (progressVal >= 0 && progressVal <= 100) progressBar.Value = progressVal;
        }

        private void DoInstall(string targetDir)
        {
            try
            {
                // 1. Kiểm tra và gỡ bỏ phiên bản cũ nếu đã tồn tại
                if (shouldRemoveOldVersion || !string.IsNullOrEmpty(detectedExistingPath))
                {
                    UninstallOldVersion(detectedExistingPath ?? targetDir);
                }
                else
                {
                    UpdateStatus("Đang kiểm tra và đóng ứng dụng nếu đang chạy...", 10);
                    try
                    {
                        foreach (var p in Process.GetProcessesByName("PassportScannerApp"))
                        {
                            try { p.Kill(); p.WaitForExit(3000); } catch { }
                        }
                    }
                    catch { }
                }

                // 2. Giải nén gói dữ liệu payload
                UpdateStatus("Đang giải nén tập tin chương trình...", 25);
                if (!Directory.Exists(targetDir))
                {
                    Directory.CreateDirectory(targetDir);
                }

                string tempZip = Path.Combine(Path.GetTempPath(), "idcapture_payload_" + Guid.NewGuid().ToString("N") + ".zip");
                using (Stream zipStream = Assembly.GetExecutingAssembly().GetManifestResourceStream("app_payload.zip"))
                {
                    if (zipStream == null)
                    {
                        throw new Exception("Không tìm thấy gói dữ liệu cài đặt app_payload.zip nhúng trong bộ cài!");
                    }
                    using (FileStream fs = new FileStream(tempZip, FileMode.Create, FileAccess.Write))
                    {
                        zipStream.CopyTo(fs);
                    }
                }

                UpdateStatus("Đang sao chép các tệp tin vào thư mục cài đặt...", 45);
                ExtractZipFile(tempZip, targetDir);
                try { if (File.Exists(tempZip)) File.Delete(tempZip); } catch { }

                // Đảm bảo app.ico luôn có mặt trong thư mục cài đặt
                string appIcoDest = Path.Combine(targetDir, "app.ico");
                if (!File.Exists(appIcoDest))
                {
                    try
                    {
                        using (Stream s = Assembly.GetExecutingAssembly().GetManifestResourceStream("app.ico"))
                        {
                            if (s != null)
                            {
                                using (FileStream fs = new FileStream(appIcoDest, FileMode.Create, FileAccess.Write))
                                {
                                    s.CopyTo(fs);
                                }
                            }
                        }
                    }
                    catch { }
                }

                // 2.1 Đồng bộ dữ liệu cảm biến máy quét vào C:\ProgramData\ID_Capture (BẮT BUỘC cho ScanDll.dll đọc brightness_data.dat, calibrate_data.dat để tránh lỗi -2017)
                UpdateStatus("Đang đồng bộ dữ liệu cảm biến máy quét (ProgramData)...", 50);
                try
                {
                    string commonAppData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
                    string pdDir = Path.Combine(commonAppData, "ID_Capture");
                    if (!Directory.Exists(pdDir)) Directory.CreateDirectory(pdDir);

                    string[] datFiles = Directory.GetFiles(targetDir, "*.dat");
                    foreach (string src in datFiles)
                    {
                        string dest = Path.Combine(pdDir, Path.GetFileName(src));
                        try { File.Copy(src, dest, true); } catch { }
                    }

                    string[] iniFiles = new string[] { "IDC_Image_Process.ini", "IDC_Focus_Tune.ini" };
                    foreach (string ini in iniFiles)
                    {
                        string src = Path.Combine(targetDir, ini);
                        if (File.Exists(src))
                        {
                            string dest = Path.Combine(pdDir, ini);
                            try { File.Copy(src, dest, true); } catch { }
                        }
                    }

                    string idcDll = Path.Combine(targetDir, "IDC_Image_Process.dll");
                    if (File.Exists(idcDll))
                    {
                        string dest = Path.Combine(pdDir, "IDC_Image_Process.dll");
                        try { File.Copy(idcDll, dest, true); } catch { }
                    }

                    // Cấp quyền Full Control cho thư mục ProgramData\ID_Capture
                    try
                    {
                        ProcessStartInfo psiAclPd = new ProcessStartInfo
                        {
                            FileName = "icacls.exe",
                            Arguments = string.Format("\"{0}\" /grant *S-1-5-32-545:(OI)(CI)F /T /C /Q", pdDir),
                            CreateNoWindow = true,
                            UseShellExecute = false
                        };
                        using (Process p = Process.Start(psiAclPd))
                        {
                            p.WaitForExit(5000);
                        }
                    }
                    catch { }
                }
                catch { }

                // Cấp quyền Full Control cho thư mục cài đặt để ứng dụng ghi ảnh, quét và lưu file CSV/XML không bị Windows UAC chặn
                UpdateStatus("Đang thiết lập quyền truy cập thư mục...", 60);
                try
                {
                    ProcessStartInfo psiAcl = new ProcessStartInfo
                    {
                        FileName = "icacls.exe",
                        Arguments = string.Format("\"{0}\" /grant *S-1-5-32-545:(OI)(CI)F /T /C /Q", targetDir),
                        CreateNoWindow = true,
                        UseShellExecute = false
                    };
                    using (Process p = Process.Start(psiAcl))
                    {
                        p.WaitForExit(10000);
                    }
                }
                catch { }

                // 3. Cài đặt Driver
                // 3. Cài đặt Driver
                if (chkDriver.Checked)
                {
                    UpdateStatus("Đang thêm chứng chỉ xác thực cho Driver Syscan IDC-V...", 68);
                    string cerPath = Path.Combine(targetDir, "driver", "SyscanIDC_V.cer");
                    string certutilPath = GetNativeToolPath("certutil.exe");
                    if (File.Exists(cerPath))
                    {
                        try
                        {
                            // Thêm chứng chỉ vào TrustedPublisher & Root để Windows tin cậy driver 100%
                            ProcessStartInfo psiCert1 = new ProcessStartInfo(certutilPath, string.Format("-addstore -f \"TrustedPublisher\" \"{0}\"", cerPath))
                            { CreateNoWindow = true, UseShellExecute = false };
                            using (Process p = Process.Start(psiCert1)) { p.WaitForExit(5000); }

                            ProcessStartInfo psiCert2 = new ProcessStartInfo(certutilPath, string.Format("-addstore -f \"Root\" \"{0}\"", cerPath))
                            { CreateNoWindow = true, UseShellExecute = false };
                            using (Process p = Process.Start(psiCert2)) { p.WaitForExit(5000); }
                        }
                        catch { }
                    }

                    UpdateStatus("Đang cài đặt Driver máy quét Syscan IDC-V vào hệ thống...", 72);
                    string infPath = Path.Combine(targetDir, "driver", "syscanidc_v.inf");
                    string pnpPath = GetNativeToolPath("pnputil.exe");
                    if (File.Exists(infPath))
                    {
                        try
                        {
                            ProcessStartInfo psi = new ProcessStartInfo
                            {
                                FileName = pnpPath,
                                Arguments = string.Format("/add-driver \"{0}\" /install", infPath),
                                CreateNoWindow = true,
                                UseShellExecute = false,
                                RedirectStandardOutput = true,
                                RedirectStandardError = true
                            };
                            using (Process p = Process.Start(psi))
                            {
                                p.WaitForExit(30000);
                            }

                            // Quét lại thiết bị USB để nhận diện máy quét ngay lập tức nếu đang cắm cáp
                            ProcessStartInfo psiScan = new ProcessStartInfo
                            {
                                FileName = pnpPath,
                                Arguments = "/scan-devices",
                                CreateNoWindow = true,
                                UseShellExecute = false
                            };
                            using (Process p = Process.Start(psiScan))
                            {
                                p.WaitForExit(10000);
                            }
                        }
                        catch { }
                    }
                }

                // Kiểm tra và cài đặt gói Windows AI OCR nếu máy mới chưa có
                UpdateStatus("Đang kiểm tra và cài đặt gói nhận diện AI Windows OCR...", 78);
                try
                {
                    string dismPath = GetNativeToolPath("dism.exe");
                    ProcessStartInfo psiOcr = new ProcessStartInfo(dismPath, "/Online /Add-Capability /CapabilityName:Language.OCR~~~en-US~0.0.1.0")
                    {
                        CreateNoWindow = true,
                        UseShellExecute = false
                    };
                    using (Process p = Process.Start(psiOcr))
                    {
                        p.WaitForExit(35000);
                    }
                }
                catch { }

                // 4. Khởi tạo biểu tượng lối tắt (Shortcuts)
                UpdateStatus("Đang thiết lập biểu tượng lối tắt (Desktop & Start Menu)...", 85);
                string exePath = Path.Combine(targetDir, "PassportScannerApp.exe");
                string icoPath = Path.Combine(targetDir, "app.ico");
                if (!File.Exists(icoPath)) icoPath = exePath;

                // Xóa triệt để mọi shortcut cũ ở cả User Desktop và Public Desktop để đảm bảo không bao giờ bị nhân đôi
                string userDesktop = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
                string commonDesktop = Environment.GetFolderPath(Environment.SpecialFolder.CommonDesktopDirectory);
                try { if (!string.IsNullOrEmpty(userDesktop)) File.Delete(Path.Combine(userDesktop, "Passport Scanner (ID-Capture).lnk")); } catch { }
                try { if (!string.IsNullOrEmpty(commonDesktop)) File.Delete(Path.Combine(commonDesktop, "Passport Scanner (ID-Capture).lnk")); } catch { }

                if (chkDesktop.Checked)
                {
                    // Tạo DUY NHẤT 1 shortcut trên Desktop:
                    // Ưu tiên Common Desktop (mọi user), nếu không có mới dùng User Desktop
                    if (!string.IsNullOrEmpty(commonDesktop) && Directory.Exists(commonDesktop))
                    {
                        CreateShortcut(Path.Combine(commonDesktop, "Passport Scanner (ID-Capture).lnk"), exePath, targetDir, icoPath);
                    }
                    else if (!string.IsNullOrEmpty(userDesktop) && Directory.Exists(userDesktop))
                    {
                        CreateShortcut(Path.Combine(userDesktop, "Passport Scanner (ID-Capture).lnk"), exePath, targetDir, icoPath);
                    }
                }

                // Xóa sạch Start Menu cũ trước khi tạo
                string commonStart = Environment.GetFolderPath(Environment.SpecialFolder.CommonPrograms);
                string userStart = Environment.GetFolderPath(Environment.SpecialFolder.Programs);
                try { if (!string.IsNullOrEmpty(userStart)) { string d = Path.Combine(userStart, "Viettechsoft"); if (Directory.Exists(d)) Directory.Delete(d, true); } } catch { }
                try { if (!string.IsNullOrEmpty(commonStart)) { string d = Path.Combine(commonStart, "Viettechsoft"); if (Directory.Exists(d)) Directory.Delete(d, true); } } catch { }

                if (chkStartMenu.Checked)
                {
                    // Tạo DUY NHẤT 1 shortcut trong Start Menu: ưu tiên Common Programs
                    if (!string.IsNullOrEmpty(commonStart) && Directory.Exists(commonStart))
                    {
                        string startFolder = Path.Combine(commonStart, "Viettechsoft");
                        if (!Directory.Exists(startFolder)) Directory.CreateDirectory(startFolder);
                        CreateShortcut(Path.Combine(startFolder, "Passport Scanner (ID-Capture).lnk"), exePath, targetDir, icoPath);
                    }
                    else if (!string.IsNullOrEmpty(userStart) && Directory.Exists(userStart))
                    {
                        string userFolder = Path.Combine(userStart, "Viettechsoft");
                        if (!Directory.Exists(userFolder)) Directory.CreateDirectory(userFolder);
                        CreateShortcut(Path.Combine(userFolder, "Passport Scanner (ID-Capture).lnk"), exePath, targetDir, icoPath);
                    }
                }

                // 5. Tạo file gỡ cài đặt và Đăng ký Registry
                UpdateStatus("Đang đăng ký thông tin phần mềm vào Windows...", 95);
                try
                {
                    CreateUninstallBatch(targetDir);
                    RegisterUninstallInfo(targetDir, exePath, icoPath);
                }
                catch { }

                // Làm mới bộ đệm Icon của Windows Explorer ngay lập tức
                try
                {
                    SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, IntPtr.Zero, IntPtr.Zero);
                }
                catch { }

                UpdateStatus("Cài đặt thành công toàn bộ phần mềm và Driver!", 100);

                this.BeginInvoke(new Action(() =>
                {
                    isFinished = true;
                    btnInstall.Text = "Hoàn tất";
                    btnInstall.Enabled = true;
                    btnCancel.Visible = false;

                    string finishMsg = "Đã cài đặt thành công phần mềm Passport Scanner (ID-Capture) và Driver máy quét!\n\nThư mục: " + targetDir;
                    if (IsMemoryIntegrityEnabled())
                    {
                        finishMsg += "\n\n⚠️ LƯU Ý WINDOWS 11:\nTính năng 'Tính toàn vẹn bộ nhớ' (Core Isolation / Memory Integrity) đang BẬT trên máy tính này.\nNếu cắm máy quét mà phần mềm báo chưa kết nối USB, vui lòng vào:\nWindows Security > Device Security > Core Isolation\nvà chuyển 'Memory Integrity' sang TẮT, sau đó khởi động lại máy tính.";
                    }
                    MessageBox.Show(this, finishMsg, "Cài đặt thành công", MessageBoxButtons.OK, MessageBoxIcon.Information);
                }));
            }
            catch (Exception ex)
            {
                this.BeginInvoke(new Action(() =>
                {
                    btnInstall.Enabled = true;
                    btnCancel.Enabled = true;
                    isInstalling = false;
                    MessageBox.Show(this, "Có lỗi trong quá trình cài đặt:\n" + ex.Message, "Lỗi cài đặt", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }));
            }
        }

        private static void ExtractZipFile(string zipPath, string targetDir)
        {
            try
            {
                using (ZipArchive archive = ZipFile.OpenRead(zipPath))
                {
                    foreach (ZipArchiveEntry entry in archive.Entries)
                    {
                        string fullPath = Path.Combine(targetDir, entry.FullName.Replace('/', '\\'));
                        if (string.IsNullOrEmpty(entry.Name))
                        {
                            if (!Directory.Exists(fullPath)) Directory.CreateDirectory(fullPath);
                        }
                        else
                        {
                            string parent = Path.GetDirectoryName(fullPath);
                            if (!Directory.Exists(parent)) Directory.CreateDirectory(parent);
                            entry.ExtractToFile(fullPath, true);
                        }
                    }
                }
                return;
            }
            catch { }

            // Fallback sang tar.exe
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo
                {
                    FileName = "tar.exe",
                    Arguments = string.Format("-xf \"{0}\" -C \"{1}\"", zipPath, targetDir),
                    CreateNoWindow = true,
                    UseShellExecute = false
                };
                using (Process p = Process.Start(psi))
                {
                    p.WaitForExit(60000);
                }
            }
            catch { }
        }

        private static bool CreateShortcut(string shortcutPath, string targetExe, string workDir, string iconPath)
        {
            try
            {
                string dir = Path.GetDirectoryName(shortcutPath);
                if (!Directory.Exists(dir)) Directory.CreateDirectory(dir);

                Type shellType = Type.GetTypeFromProgID("WScript.Shell");
                if (shellType != null)
                {
                    object shell = Activator.CreateInstance(shellType);
                    object shortcut = shellType.InvokeMember("CreateShortcut", BindingFlags.InvokeMethod, null, shell, new object[] { shortcutPath });
                    Type scType = shortcut.GetType();
                    scType.InvokeMember("TargetPath", BindingFlags.SetProperty, null, shortcut, new object[] { targetExe });
                    scType.InvokeMember("WorkingDirectory", BindingFlags.SetProperty, null, shortcut, new object[] { workDir });
                    if (!string.IsNullOrEmpty(iconPath) && File.Exists(iconPath))
                    {
                        scType.InvokeMember("IconLocation", BindingFlags.SetProperty, null, shortcut, new object[] { iconPath + ",0" });
                    }
                    else
                    {
                        scType.InvokeMember("IconLocation", BindingFlags.SetProperty, null, shortcut, new object[] { targetExe + ",0" });
                    }
                    scType.InvokeMember("Description", BindingFlags.SetProperty, null, shortcut, new object[] { "Passport Scanner (ID-Capture) - Viettechsoft" });
                    scType.InvokeMember("Save", BindingFlags.InvokeMethod, null, shortcut, null);
                    if (File.Exists(shortcutPath)) return true;
                }
            }
            catch { }

            // Fallback via VBScript
            try
            {
                string vbsFile = Path.Combine(Path.GetTempPath(), "mklink_" + Guid.NewGuid().ToString("N") + ".vbs");
                string vbs = string.Format(
                    "Set WshShell = CreateObject(\"WScript.Shell\")\r\n" +
                    "Set oLink = WshShell.CreateShortcut(\"{0}\")\r\n" +
                    "oLink.TargetPath = \"{1}\"\r\n" +
                    "oLink.WorkingDirectory = \"{2}\"\r\n" +
                    "oLink.IconLocation = \"{3},0\"\r\n" +
                    "oLink.Description = \"Passport Scanner (ID-Capture) - Viettechsoft\"\r\n" +
                    "oLink.Save\r\n",
                    shortcutPath.Replace("\\", "\\\\"),
                    targetExe.Replace("\\", "\\\\"),
                    workDir.Replace("\\", "\\\\"),
                    (File.Exists(iconPath) ? iconPath : targetExe).Replace("\\", "\\\\")
                );
                File.WriteAllText(vbsFile, vbs, Encoding.Default);
                ProcessStartInfo psi = new ProcessStartInfo("cscript.exe", "//Nologo \"" + vbsFile + "\"")
                {
                    CreateNoWindow = true,
                    UseShellExecute = false
                };
                using (Process p = Process.Start(psi))
                {
                    p.WaitForExit(5000);
                }
                try { File.Delete(vbsFile); } catch { }
                return File.Exists(shortcutPath);
            }
            catch { return false; }
        }

        private static void CreateUninstallBatch(string targetDir)
        {
            try
            {
                string uninstPath = Path.Combine(targetDir, "uninstall.bat");
                string content =
                    "@echo off\r\n" +
                    "echo Dang go bo phan mem Passport Scanner (ID-Capture)...\r\n" +
                    "taskkill /f /im PassportScannerApp.exe 2>nul\r\n" +
                    "del /f /q \"%PUBLIC%\\Desktop\\Passport Scanner (ID-Capture).lnk\" 2>nul\r\n" +
                    "del /f /q \"%USERPROFILE%\\Desktop\\Passport Scanner (ID-Capture).lnk\" 2>nul\r\n" +
                    "rmdir /s /q \"%PROGRAMDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Viettechsoft\" 2>nul\r\n" +
                    "rmdir /s /q \"%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Viettechsoft\" 2>nul\r\n" +
                    "reg delete \"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Viettechsoft_ID_Capture\" /f 2>nul\r\n" +
                    "echo.\r\n" +
                    "echo Da go bo loi tat va thong tin dang ky thanh cong.\r\n" +
                    "echo Thu muc: " + targetDir + "\r\n" +
                    "pause\r\n";
                File.WriteAllText(uninstPath, content, Encoding.GetEncoding(1258));
            }
            catch { }
        }

        private static void RegisterUninstallInfo(string targetDir, string exePath, string icoPath)
        {
            try
            {
                using (RegistryKey key = Registry.LocalMachine.CreateSubKey(@"Software\Microsoft\Windows\CurrentVersion\Uninstall\Viettechsoft_ID_Capture"))
                {
                    if (key != null)
                    {
                        key.SetValue("DisplayName", "Passport Scanner (ID-Capture)");
                        key.SetValue("DisplayVersion", "1.0");
                        key.SetValue("Publisher", "Viettechsoft");
                        key.SetValue("InstallLocation", targetDir);
                        key.SetValue("DisplayIcon", icoPath + ",0");
                        key.SetValue("UninstallString", "\"" + Path.Combine(targetDir, "uninstall.bat") + "\"");
                        key.SetValue("HelpLink", "https://viettechsoft.com");
                        key.SetValue("Contact", "info@viettechsoft.com | Hotline: 0976.098.886");
                    }
                }
            }
            catch { }
        }

        private static string GetNativeToolPath(string exeName)
        {
            string winDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            // Sysnative directs a 32-bit process to the real 64-bit System32 directory
            string sysnative = Path.Combine(winDir, "Sysnative", exeName);
            if (File.Exists(sysnative)) return sysnative;
            string sys32 = Path.Combine(winDir, "System32", exeName);
            if (File.Exists(sys32)) return sys32;
            return exeName;
        }

        private static bool IsMemoryIntegrityEnabled()
        {
            try
            {
                using (var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity"))
                {
                    if (key != null)
                    {
                        object val = key.GetValue("Enabled");
                        if (val != null && Convert.ToInt32(val) == 1) return true;
                    }
                }
            }
            catch { }
            return false;
        }
    }

    static class Program
    {
        [STAThread]
        static void Main()
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new SetupForm());
        }
    }
}
