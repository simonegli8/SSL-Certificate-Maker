using Avalonia;
using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Media.Imaging;
using Avalonia.Platform;
using Avalonia.Platform.Storage;
using Avalonia.Styling;
using Avalonia.Threading;
using Avalonia.VisualTree;
using AvaloniaDialogs.Views;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using SSLCertificateMaker.Library;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Security.Cryptography.X509Certificates;

namespace SSLCertificateMaker.Avalonia
{
    public partial class MainWindow : Window
    {
        private const string SelfSignedLabel = "None (Self-Signed)";
        private const string MakeButtonText = "Make Certificate";
        private const string MakeCRLButtonText = "Make Certificate Revocation List";
        private const string CancelButtonText = "Cancel";

        public static string CaDirectory => CertMaker.CaDirectory;
        public static string CertDirectory => CertMaker.CertDirectory;
        public static string RevokedDirectory => CertMaker.RevokedDirectory;

        public static bool IsWindows => OSInfo.IsWindows;
        public static bool IsLinux => OSInfo.IsLinux;
        public static bool IsMac => OSInfo.IsMac;

        private CancellationTokenSource? _cts;

        private readonly MultiSelectIntItem[] KeyUsageOptions = new[]
        {
            new MultiSelectIntItem("EncipherOnly (1)", KeyUsage.EncipherOnly),
            new MultiSelectIntItem("CRL Signing (2)", KeyUsage.CrlSign),
            new MultiSelectIntItem("Certificate Signing (4)", KeyUsage.KeyCertSign),
            new MultiSelectIntItem("KeyAgreement (8)", KeyUsage.KeyAgreement),
            new MultiSelectIntItem("DataEncipherment (16)", KeyUsage.DataEncipherment),
            new MultiSelectIntItem("KeyEncipherment (32)", KeyUsage.KeyEncipherment),
            new MultiSelectIntItem("NonRepudiation (64)", KeyUsage.NonRepudiation),
            new MultiSelectIntItem("DigitalSignature (128)", KeyUsage.DigitalSignature),
            new MultiSelectIntItem("DecipherOnly (32768)", KeyUsage.DecipherOnly)
        };

        private readonly MultiSelectKeyPurposeItem[] ExtendedKeyUsageOptions = new[]
        {
            new MultiSelectKeyPurposeItem("Any Extended Key Usage", KeyPurposeID.AnyExtendedKeyUsage),
            new MultiSelectKeyPurposeItem("Client Auth", KeyPurposeID.id_kp_clientAuth),
            new MultiSelectKeyPurposeItem("Code Signing", KeyPurposeID.id_kp_codeSigning),
            new MultiSelectKeyPurposeItem("Email Protection", KeyPurposeID.id_kp_emailProtection),
            new MultiSelectKeyPurposeItem("Ipsec End System", KeyPurposeID.id_kp_ipsecEndSystem),
            new MultiSelectKeyPurposeItem("Ipsec Tunnel", KeyPurposeID.id_kp_ipsecTunnel),
            new MultiSelectKeyPurposeItem("Ipsec User", KeyPurposeID.id_kp_ipsecUser),
            new MultiSelectKeyPurposeItem("Mac Address", KeyPurposeID.id_kp_macAddress),
            new MultiSelectKeyPurposeItem("Ocsp Signing", KeyPurposeID.id_kp_OCSPSigning),
            new MultiSelectKeyPurposeItem("Server Auth", KeyPurposeID.id_kp_serverAuth),
            new MultiSelectKeyPurposeItem("Smart Card Logon", KeyPurposeID.id_kp_smartcardlogon),
            new MultiSelectKeyPurposeItem("Time Stamping", KeyPurposeID.id_kp_timeStamping)
        };

        public static readonly StyledProperty<string> DeleteIconSourceProperty =
            AvaloniaProperty.Register<MainWindow, string>(nameof(DeleteIconSource));

        public string DeleteIconSource
        {
            get => GetValue(DeleteIconSourceProperty);
            set => SetValue(DeleteIconSourceProperty, value);
        }
        public RevokeItemsList RevokeItems = new RevokeItemsList();

        public MainWindow()
        {
            InitializeComponent();

            InitializeUi();
        }

        async Task IssuerComboSelectionChanged(ComboBox issuerCombo)
        {
            {
                var item = issuerCombo.SelectedItem as string;
                if (item == OpenFile)
                {
                    var topLevel = TopLevel.GetTopLevel(this);

                    var folder = await topLevel.StorageProvider.TryGetFolderFromPathAsync(CertDirectory);
                    var files = await topLevel.StorageProvider.OpenFilePickerAsync(
                        new FilePickerOpenOptions
                        {
                            Title = "Select CA Certificate",
                            SuggestedStartLocation = folder,
                            FileTypeFilter = new[]
                            {
                                new FilePickerFileType("Certificate Files")
                                {
                                    Patterns = IsWindows ? new[] { "*.pfx", "*.key", "*.cer" } :
                                        new[] { "*.pfx", "*.key", "*.cer",
                                            "application/pkix-cert", "application/x-x509-ca-cert",
                                            "application/x-pkcs12", "application/pkcs12"
                                    }
                                },
                                new FilePickerFileType("All Files")
                                {
                                    Patterns = IsWindows ? new[] { "*.*" } : new[] { "*.*", "*" }
                                }
                                }
                        });
                    if (files != null && files.Count > 0)
                    {
                        var localPath = files[0].TryGetLocalPath();
                        var selectedFile = Path.GetFileName(localPath);
                        var capath = Path.GetFullPath(CaDirectory);
                        var ext = Path.GetExtension(selectedFile);
                        if (ext.Equals(".pfx", StringComparison.OrdinalIgnoreCase))
                        {
                            File.Copy(localPath, Path.Combine(capath, selectedFile), true);
                            await Dispatcher.UIThread.InvokeAsync(() =>
                            {
                                issuerCombo.SelectedItem = null;
                                PopulateIssuerDropdown(issuerCombo);
                                issuerCombo.SelectedItem = selectedFile;
                            });
                        }
                        else if (ext.Equals(".key", StringComparison.OrdinalIgnoreCase))
                        {
                            var cerfile = Path.ChangeExtension(localPath, ".cer");
                            if (!File.Exists(cerfile)) await ShowError("Missing *.cer File", "The selected .key file does not have a corresponding .cer file in the same location. Please ensure both .key and .cer files are present.");
                            else
                            {
                                File.Copy(localPath, Path.Combine(capath, selectedFile), true);
                                File.Copy(cerfile, Path.Combine(capath, Path.ChangeExtension(selectedFile, ".cer")), true);
                                await Dispatcher.UIThread.InvokeAsync(() =>
                                {
                                    issuerCombo.SelectedItem = null;
                                    PopulateIssuerDropdown(issuerCombo);
                                    issuerCombo.SelectedItem = selectedFile;
                                });
                            }
                        }
                        else if (ext.Equals(".cer", StringComparison.OrdinalIgnoreCase))
                        {
                            var keyfile = Path.ChangeExtension(localPath, ".cer");
                            if (!File.Exists(keyfile)) ShowError("Missing *.key File", "The selected .cer file does not have a corresponding .key file in the same location. Please ensure both .key and .cer files are present.");
                            else
                            {
                                File.Copy(localPath, Path.Combine(capath, selectedFile), true);
                                File.Copy(keyfile, Path.Combine(capath, Path.ChangeExtension(selectedFile, ".key")), true);
                                await Dispatcher.UIThread.InvokeAsync(() =>
                                {
                                    issuerCombo.SelectedItem = null;
                                    PopulateIssuerDropdown(issuerCombo);
                                    issuerCombo.SelectedItem = selectedFile;
                                });
                            }
                        }
                    }
                }

                if (issuerCombo.SelectedValue == OpenFile)
                {
                    if (issuerCombo == IssuerCombo) issuerCombo.SelectedItem = SelfSignedLabel;
                    else issuerCombo.SelectedIndex = 0;
                }
            }
        }

        bool userClickedTab = false;
        private void InitializeUi()
        {
            this.WindowStartupLocation = WindowStartupLocation.CenterScreen;

            var version = typeof(MainWindow).Assembly.GetName().Version;
            Title += $" {version.Major}.{version.Minor}";

            // Dates
            ValidFromDatePicker.SelectedDate = DateTime.Today.AddYears(-10);
            ValidToDatePicker.SelectedDate = DateTime.Today.AddYears(500);
            LastUpdateDatePicker.SelectedDate = DateTime.Today;
            NextUpdateDatePicker.SelectedDate = DateTime.Today.AddYears(500);

            // Key strength
            KeyStrengthComboBox.ItemsSource = new[] { "1024", "2048", "3072", "4096", "8192", "16384" };
            KeyStrengthComboBox.SelectedIndex = 1;

            // Output type
            OutputTypeComboBox.ItemsSource = new[] { ".pfx", ".cer, .key" };
            OutputTypeComboBox.SelectedIndex = 0;
            OutputTypeComboBox.SelectionChanged += OutputTypeComboBox_OnSelectionChanged;
            UpdatePasswordEnabled();

            // Key usage lists
            KeyUsageListBox.ItemsSource = KeyUsageOptions;
            ExtendedKeyUsageListBox.ItemsSource = ExtendedKeyUsageOptions;
            KeyUsageListBox.SelectionChanged += KeyUsageSelectionChanged;
            ExtendedKeyUsageListBox.SelectionChanged += KeyUsageSelectionChanged;

            // Buttons
            MakeCertButton.Content = MakeButtonText;
            MakeCertButton.Click += MakeCertButton_OnClick;
            AddCRLButton.Click += AddCRLItem_OnClick;
            MakeCRLButton.Click += MakeCRLButton_OnClick;
            WebServerPresetButton.Click += WebServerPresetButton_OnClick;
            CaPresetButton.Click += CaPresetButton_OnClick;
            ConvertButton.Click += Convert;
            KeyUsageEditButton.Click += (sender, args) =>
            {
                if (ExtendedKeyUsageBox.IsVisible) ExtendedKeyUsageBox.IsVisible = false;
                if (AdvancedBox.IsVisible) AdvancedBox.IsVisible = false;
                KeyUsageBox.IsVisible = !KeyUsageBox.IsVisible;
            };
            ExtendedKeyUsageEditButton.Click += (sender, args) =>
            {
                if (KeyUsageBox.IsVisible) KeyUsageBox.IsVisible = false;
                if (AdvancedBox.IsVisible) AdvancedBox.IsVisible = false;
                ExtendedKeyUsageBox.IsVisible = !ExtendedKeyUsageBox.IsVisible;
            };
            AdvancedEditButton.Click += (_, _) =>
            {
                if (ExtendedKeyUsageBox.IsVisible) ExtendedKeyUsageBox.IsVisible = false;
                if (KeyUsageBox.IsVisible) KeyUsageBox.IsVisible = false;
                AdvancedBox.IsVisible = !AdvancedBox.IsVisible;
            };
            CertificateCombo.DropDownOpened += (_, _) => PopulateConvertDropdown();
            CertificateCombo.SelectionChanged += (_, args) =>
            {
                var item = CertificateCombo.SelectedItem as string;
                if (item == null)
                {
                    ConvertButton.Content = "Convert";
                }
                else if (item.EndsWith(".pfx", StringComparison.OrdinalIgnoreCase))
                {
                    ConvertButton.Content = "Convert to .cer, .key";
                }
                else
                {
                    ConvertButton.Content = "Convert to .pfx";
                }
            };
            foreach (var tabItem in tabControl.Items.OfType<TabItem>())
            {
                tabItem.PointerReleased += (sender, e) =>
                {
                    var control = sender as Visual;

                    var hit = e.GetCurrentPoint(tabControl);

                    Dispatcher.UIThread.Invoke(() => SetStatus(""));
                };
            }
            /*tabControl.SelectionChanged += (_, _) =>
            {
                if (!userClickedTab) return;
                userClickedTab = false;
                SetStatus("");
            };*/

            IssuerCombo.SelectionChanged += async void (_, _) => await IssuerComboSelectionChanged(IssuerCombo);
            CRLIssuerCombo.SelectionChanged += async void (_, _) => await IssuerComboSelectionChanged(CRLIssuerCombo);

            StatusTextBlock.Text = string.Empty;
            StopProgress();

            ApplyWebServerPreset();
            PopulateIssuerDropdown(IssuerCombo);
            PopulateIssuerDropdown(CRLIssuerCombo);

            Application.Current!.PropertyChanged += SetTheme;
            SetTheme();
        }

        protected override void OnClosed(EventArgs e)
        {
            base.OnClosed(e);
            Application.Current!.PropertyChanged -= SetTheme;
        }
        private void KeyUsageSelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (sender == KeyUsageListBox)
            {
                txtKeyUsage.Text = string.Join(", ", KeyUsageListBox.SelectedItems
                    .OfType<MultiSelectIntItem>()
                    .Select(item => item.Key));
            }
            else txtExtendedKeyUsage.Text = string.Join(", ", ExtendedKeyUsageListBox.SelectedItems
                .OfType<MultiSelectKeyPurposeItem>()
                .Select(item => item.Key));
        }
        private void OutputTypeComboBox_OnSelectionChanged(object? sender, SelectionChangedEventArgs e)
        {
            UpdatePasswordEnabled();
        }

        private void SetTheme(object sender = null, AvaloniaPropertyChangedEventArgs e = null)
        {
            if (e == null || e.Property.Name == nameof(Application.ActualThemeVariant))
            {

                var isDark = Application.Current?.ActualThemeVariant == ThemeVariant.Dark;
                if (isDark)
                {
                    PenImage1.Source = PenImage2.Source = PenImage3.Source = new Bitmap(AssetLoader.Open(new Uri("avares://SSLCertificateMaker.Avalonia/pen-white.png")));
                }
                else
                {
                    PenImage1.Source = PenImage2.Source = PenImage3.Source = new Bitmap(AssetLoader.Open(new Uri("avares://SSLCertificateMaker.Avalonia/pen.png")));
                }
                PopulateRevokeItems();
            }
        }
        private void UpdatePasswordEnabled()
        {
            if (OutputTypeComboBox.SelectedItem is string s)
            {
                PasswordTextBox.IsEnabled = s == ".pfx";
            }
        }

        public const string OpenFile = "Open File ...";
        private void PopulateIssuerDropdown(ComboBox issuerCombo)
        {
            var previouslySelected = issuerCombo.SelectedItem as string;
            var items = new List<string>();
            if (issuerCombo == IssuerCombo) items.Add(SelfSignedLabel);

            foreach (var fi in new DirectoryInfo(CaDirectory).GetFiles())
            {
                if (string.Equals(fi.Extension, ".pfx", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(fi.Extension, ".key", StringComparison.OrdinalIgnoreCase))
                {
                    items.Add(fi.Name);
                }
            }

            items.Sort(StringComparer.OrdinalIgnoreCase);
            items.Add(OpenFile);

            issuerCombo.ItemsSource = items;
            if (!string.IsNullOrEmpty(previouslySelected) && items.Contains(previouslySelected))
            {
                issuerCombo.SelectedItem = previouslySelected;
            }
            else
            {
                if (issuerCombo == IssuerCombo)
                {
                    issuerCombo.SelectedItem = SelfSignedLabel;
                }
                else
                {
                    issuerCombo.SelectedIndex = 0;
                }
            }
        }
        private void PopulateRevokeItems()
        {
            Dispatcher.UIThread.Invoke(() =>
            {
                using var mutex = new NamedMutex();
                RevokeItems.Load();
                RevocationListBox.ItemsSource = RevokeItems.Observable;
            });
        }
        private void PopulateConvertDropdown()
        {
            var previouslySelected = CertificateCombo.SelectedItem as string;
            var items = new List<string>();

            foreach (var fi in new DirectoryInfo(CertDirectory).GetFiles())
            {
                if (string.Equals(fi.Extension, ".pfx", StringComparison.OrdinalIgnoreCase)) items.Add(fi.Name);
                else if (string.Equals(fi.Extension, ".key", StringComparison.OrdinalIgnoreCase) && File.Exists(Path.ChangeExtension(fi.FullName, ".cer")))
                {
                    items.Add(fi.Name + " & .cer");
                }
            }

            items.Sort(StringComparer.OrdinalIgnoreCase);

            CertificateCombo.ItemsSource = items;
            if (!string.IsNullOrEmpty(previouslySelected) && items.Contains(previouslySelected))
            {
                CertificateCombo.SelectedItem = previouslySelected;
            }
            else
            {
                CertificateCombo.SelectedIndex = items.Count > 1 ? 1 : 0;
            }
        }


        private async void MakeCertButton_OnClick(object? sender, RoutedEventArgs e)
        {
            if (Equals(MakeCertButton.Content, MakeButtonText))
            {
                var domains = GetCleanDomainArray();
                if (domains.Length == 0)
                {
                    await SetStatus("No domain names were entered (at least 'localhost' is recommended).");
                    return;
                }

                if (KeyStrengthComboBox.SelectedItem is not string keyStrengthStr ||
                    !int.TryParse(keyStrengthStr, out var keyStrength))
                {
                    await SetStatus("Invalid key strength.");
                    return;
                }

                var validFrom = ValidFromDatePicker.SelectedDate ?? DateTime.Today;
                var validTo = ValidToDatePicker.SelectedDate ?? DateTime.Today.AddYears(1);

                var outputType = OutputTypeComboBox.SelectedItem as string ?? ".pfx";
                var issuer = IssuerCombo.SelectedItem as string ?? SelfSignedLabel;
                if (issuer == OpenFile) issuer = SelfSignedLabel;

                var keyUsage = KeyUsageListBox.SelectedItems
                    .OfType<MultiSelectIntItem>()
                    .Select(i => i.Value)
                    .Aggregate(0, (acc, v) => acc | v);

                var extendedKeyUsage = ExtendedKeyUsageListBox.SelectedItems
                    .OfType<MultiSelectKeyPurposeItem>()
                    .Select(i => i.Value)
                    .ToArray();

                var args = new MakeCertArgs(
                    keyStrength,
                    validFrom.Date,
                    validTo.Date,
                    domains,
                    PasswordTextBox.Text ?? string.Empty,
                    outputType == ".cer, .key",
                    issuer,
                    keyUsage,
                    extendedKeyUsage,
                    CRLUrl.Text,
                    OCSPUrl.Text
                )
                {
                    OutputPath = CertDirectory
                };

                /*if (LooksLikeCa(args))
                {
                    // In WinForms this was user-confirmed; here we automatically place CAs into the CA folder.
                    args.OutputPath = CaDirectory;
                }*/

                MakeCertButton.Content = CancelButtonText;

                StartProgress();
                await SetStatus("Generating certificate…");

                _cts = new CancellationTokenSource();

                try
                {
                    await MakeCertificate(args, _cts.Token);
                    if (_cts.IsCancellationRequested)
                    {
                        await SetStatus("Aborted");
                    }
                    else
                    {
                        //await SetStatus(string.Empty);
                    }
                }
                catch (Exception ex)
                {
                    await SetStatus("An error occurred while generating the certificate.");
                    // Optionally log ex.ToString() somewhere
                }
                finally
                {
                    StopProgress();
                    _cts?.Dispose();
                    _cts = null;
                }
            }
            else
            {
                MakeCertButton.IsEnabled = false;
                _cts?.Cancel();
            }
        }
        private async void AddCRLItem_OnClick(object? sender, RoutedEventArgs e)
        {
            IReadOnlyList<IStorageFile?> files = null;
            await Dispatcher.UIThread.InvokeAsync(async () =>
            {
                var window = TopLevel.GetTopLevel(this) as Window;
                window.WindowStartupLocation = WindowStartupLocation.CenterScreen;
                window?.Activate();
                var topLevel = TopLevel.GetTopLevel(this);
                var folder = await topLevel.StorageProvider.TryGetFolderFromPathAsync(CertDirectory);
                files = (await topLevel.StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions()
                {
                    Title = "Revoke Certificates",
                    SuggestedStartLocation = folder,
                    AllowMultiple = true,
                    FileTypeFilter =
                        new[]
                        {
                            new FilePickerFileType("Certificate Files") {
                                Patterns = IsWindows ? new[] { "*.cer", "*.pfx" } :
                                    new[] { "*.cer", "*.pfx",
                                        "application/pkix-cert", "application/x-x509-ca-cert",
                                        "application/x-pkcs12", "application/pkcs12" }
                            },
                            new FilePickerFileType("All Files") {
                                Patterns = IsWindows ? new[] { "*.*" } : new[] { "*.*", "*" }
                            }
                        }
                }));
            });
            if (files != null && files.Count > 0)
            {
                int? reason = CrlReason.Unspecified;
                await Dispatcher.UIThread.InvokeAsync(async () =>
                {
                    var reasonprompt = new CrlReasonPrompt();
                    reason = await reasonprompt.ShowDialog<int?>(this);

                    foreach (var file in files
                        .Select(f => f.TryGetLocalPath())
                        .Where(f => File.Exists(f)))
                    {
                        if (file.EndsWith(".pfx", StringComparison.OrdinalIgnoreCase) ||
                            file.EndsWith(".cer", StringComparison.OrdinalIgnoreCase))
                        {
                            string password = null;
                            X509Certificate2? cert = null;
                            if (file.EndsWith(".pfx", StringComparison.OrdinalIgnoreCase))
                            {
                                PasswordPrompt pp = new PasswordPrompt();
                                pp.PasswordLabel.Text = $"Password for {Path.GetFileName(file)}";
                                password = await pp.ShowDialog<string?>(this);
                                cert = X509CertificateLoader.LoadPkcs12CollectionFromFile(file, password)
                                    .FirstOrDefault();
                            }
                            else
                            {
                                cert = X509CertificateLoader.LoadCertificateFromFile(file);
                            }

                            using var mutex = new NamedMutex();
                            RevokeItems.Load();
                            RevokeItems.Add(new RevokeItem()
                            {
                                File = file,
                                SerialNumber = BigInteger.Parse(cert.SerialNumber, System.Globalization.NumberStyles.HexNumber),
                                Reason = reason,
                            });
                            RevokeItems.Save();
                        }
                    }
                });
            }
        }
        private async void MakeCRLButton_OnClick(object? sender, RoutedEventArgs e)
        {
            if (Equals(MakeCRLButton.Content, MakeCRLButtonText))
            {
                var lastUpdate = LastUpdateDatePicker.SelectedDate ?? DateTime.Today;
                var nextUpdate = NextUpdateDatePicker.SelectedDate ?? DateTime.Today.AddYears(1);
                var issuer = CRLIssuerCombo.SelectedItem as string;
                if (issuer == null || issuer == OpenFile)
                {
                    await ShowError("No Issuer Selecte", "Please select an issuer.");
                    return;
                }
                issuer = Path.Combine(CaDirectory, issuer);
                MakeCRLButton.Content = CancelButtonText;

                StartProgress();
                await SetStatus("Generating Certificate Revocation List…");

                _cts = new CancellationTokenSource();

                try
                {
                    await MakeCertificateRevocationList(issuer, lastUpdate, nextUpdate, RevokeItems, _cts.Token);
                    if (_cts.IsCancellationRequested)
                    {
                        await SetStatus("Aborted");
                    }
                    else
                    {
                        //await SetStatus(string.Empty);
                    }
                }
                catch (Exception ex)
                {
                    await SetStatus("An error occurred while generating the list.");
                    // Optionally log ex.ToString() somewhere
                }
                finally
                {
                    StopProgress();
                    _cts?.Dispose();
                    _cts = null;
                }
            }
            else
            {
                MakeCRLButton.IsEnabled = false;
                _cts?.Cancel();
            }
        }

        public async void Convert(object? sender, RoutedEventArgs e)
        {
            var item = CertificateCombo.SelectedItem as string;
            if (item == null) return;

            item = Regex.Replace(item, @" & \.cer$", "");
            var extension = Path.GetExtension(item);
            var sourcePath = Path.Combine(CertDirectory, item);
            CertificateBundle bundle = null;

            StartProgress();
            await SetStatus($"Converting {item}…");

            _cts = new CancellationTokenSource();

            try
            {
                if (extension == ".pfx")
                {
                    // Read pfx
                    string? password = null;
                    bool first = true;
                    while (bundle == null)
                    {
                        try
                        {
                            bundle = CertificateBundle.LoadFromPfxFile(sourcePath, password);
                        }
                        catch (ArgumentException)
                        {

                        }
                        if (bundle == null)
                        {
                            if (!first)
                            {
                                if (!await Confirm("Wrong Password", "You've entered a wrong password. Try again?")) return;
                            }
                            else first = false;
                            PasswordPrompt pp = new PasswordPrompt();
                            password = await pp.ShowDialog<string?>(this);
                            if (password == null) return;
                        }
                    }

                    // write .cer & .key
                    var fullNameWithoutExtension = Path.Combine(Path.GetDirectoryName(sourcePath), Path.GetFileNameWithoutExtension(sourcePath));
                    string fileNameCer = fullNameWithoutExtension + ".cer";
                    if (File.Exists(fileNameCer))
                    {
                        if (!await Confirm("Overwrite existing file?", "Output file \"" + fileNameCer + "\" already exists.  Overwrite?")) return;
                    }
                    string fileNameKey = fullNameWithoutExtension + ".key";
                    if (File.Exists(fileNameKey))
                    {
                        if (!await Confirm("Overwrite existing file?", "Output file \"" + fileNameKey + "\" already exists.  Overwrite?")) return;
                    }
                    File.WriteAllBytes(fileNameCer, bundle.GetPublicCertAsCerFile());
                    File.WriteAllBytes(fileNameKey, bundle.GetPrivateKeyAsKeyFile());

                    await SetStatus($"Converted to {Path.GetFileName(fileNameCer)} & {Path.GetFileName(fileNameKey)}.");
                }
                else
                {
                    // .key source
                    string cerSourcePath = Path.ChangeExtension(sourcePath, ".cer"), keySourcePath = sourcePath;
                    bundle = CertificateBundle.LoadFromCerAndKeyFiles(cerSourcePath, keySourcePath);

                    string pfxFileName = Path.ChangeExtension(sourcePath, ".pfx");
                    if (File.Exists(pfxFileName))
                    {
                        if (!await Confirm("Overwrite existing file?", "Output file \"" + pfxFileName + "\" already exists.  Overwrite?")) return;
                    }
                    File.WriteAllBytes(pfxFileName, bundle.GetPfx(null));

                    await SetStatus($"Converted to {Path.GetFileName(pfxFileName)}.");
                }
            }
            finally
            {
                StopProgress();
            }

        }
        private bool LooksLikeCa(MakeCertArgs args)
        {
            if ((args.KeyUsage & 6) != 6)
                return false;
            if (args.ExtendedKeyUsage.Length != 0)
                return false;
            return true;
        }

        private string[] GetCleanDomainArray()
        {
            return (DomainsTextBox.Text ?? string.Empty)
                .Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)
                .Select(line => line.Trim())
                .Where(line => !string.IsNullOrWhiteSpace(line))
                .ToArray();
        }

        public async Task<bool> Confirm(string title, string message)
        {
            return (await Dispatcher.UIThread.InvokeAsync(async () =>
            {
                var dialog = new TwofoldDialog
                {
                    Name = title,
                    Message = message,
                    PositiveText = "Ok",
                    NegativeText = "Cancel"
                };
                return await dialog.ShowAsync();
            })).Value;
        }

        public async Task<bool> ShowError(string title, string message)
        {
            return (await Dispatcher.UIThread.InvokeAsync(async () =>
            {
                var dialog = new TwofoldDialog
                {
                    Name = title,
                    Message = message,
                    PositiveText = "Ok",
                };
                return await dialog.ShowAsync();
            })).Value;
        }

        class PasswordFinder : IPasswordFinder
        {
            char[] _password;
            public PasswordFinder(string password)
            {
                _password = password.ToCharArray();
            }

            public char[] GetPassword() => _password;
        }
        public async Task<AsymmetricKeyParameter> LoadPrivateKey(string path)
        {
            string text = null;
            try
            {
                text = File.ReadAllText(path);
            }
            catch { }
            var m = Regex.Match(text, @"^-+\s*BEGIN\s+(?:(?<type>ENCRYPTED|RSA)\s+)?PRIVATE\s+KEY\s*-+", RegexOptions.Singleline);
            if (m.Success)
            {
                var reader = new StringReader(text);
                PemReader pemReader;
                if (m.Groups["type"].Value == "ENCRYPTED")
                {
                    var password = await Dispatcher.UIThread.InvokeAsync(async () =>
                    {
                        PasswordPrompt pp = new PasswordPrompt();
                        pp.PasswordLabel.Text = $"Password for {Path.GetFileName(path)}";
                        return await pp.ShowDialog<string?>(this);
                    });

                    pemReader = new PemReader(reader, new PasswordFinder(password));
                }
                else pemReader = new PemReader(reader);
                object obj;
                try
                {
                    obj = pemReader.ReadObject();
                }
                catch (Exception ex)
                {
                    throw new InvalidOperationException($"Unsupported key format: {ex.Message}");
                }

                return obj switch
                {
                    AsymmetricCipherKeyPair pair => pair.Private,
                    AsymmetricKeyParameter key => key,
                    _ => throw new InvalidOperationException("Unsupported key format")
                };
            }
            var bytes = File.ReadAllBytes(path);
            try
            {
                var key = PrivateKeyFactory.CreateKey(bytes);
                return key;
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException($"Unsupported key format: {ex.Message}");
            }
        }
        private async Task MakeCertificateRevocationList(string? issuer, DateTimeOffset lastUpdate, DateTimeOffset nextUpdate, RevokeItemsList items, CancellationToken cancel)
        {
            if (string.IsNullOrWhiteSpace(issuer))
            {
                await ShowError("No Issuer Selected", "Please select an issuer.");
                return;
            }
            issuer = issuer.Trim();

            var safeFileName = Path.Combine(RevokedDirectory, SafeFileName(Path.GetFileNameWithoutExtension(issuer) + ".crl"));
            Directory.CreateDirectory(RevokedDirectory);

            string? file = await Dispatcher.UIThread.InvokeAsync(async () =>
            {
                var window = TopLevel.GetTopLevel(this) as Window;
                window.WindowStartupLocation = WindowStartupLocation.CenterScreen;
                window?.Activate();
                var topLevel = TopLevel.GetTopLevel(this);
                var folder = await topLevel.StorageProvider.TryGetFolderFromPathAsync(CertDirectory);
                var file = await topLevel.StorageProvider.SaveFilePickerAsync(new FilePickerSaveOptions()
                {
                    Title = "Save Certificate Revocation List",
                    SuggestedStartLocation = folder,
                    FileTypeChoices =
                        new[]
                        {
                            new FilePickerFileType("Revocation List Files") {
                                Patterns = IsWindows ? new[] { "*.crl" } :
                                    new[] { "*.crl", "application/pkix-crl" }
                            },
                            new FilePickerFileType("All Files") {
                                Patterns = IsWindows ? new[] { "*.*" } : new[] { "*.*", "*" }
                            }
                        },
                    DefaultExtension = "crl",
                    SuggestedFileName = Path.GetFileName(safeFileName),
                    ShowOverwritePrompt = true
                });
                return file?.TryGetLocalPath();
            });
            if (file == null)
            {
                await SetStatus("Operation cancelled.");
                return;
            }

            string? password = null;
            X509Certificate2? issuercert = null;
            AsymmetricKeyParameter? privateKey = null;
            if (issuer.EndsWith(".pfx", StringComparison.OrdinalIgnoreCase))
            {
                password = await Dispatcher.UIThread.InvokeAsync(async () =>
                {
                    PasswordPrompt pp = new PasswordPrompt();
                    pp.PasswordLabel.Text = $"Password for {Path.GetFileName(issuer)}";
                    return await pp.ShowDialog<string?>(this);
                });
                issuercert = X509CertificateLoader.LoadPkcs12CollectionFromFile(issuer, password,
                    X509KeyStorageFlags.Exportable |
                    X509KeyStorageFlags.EphemeralKeySet)
                    .FirstOrDefault();
            }
            else
            {
                issuercert = X509CertificateLoader.LoadCertificateFromFile(Path.ChangeExtension(issuer, ".cer"));
                privateKey = await LoadPrivateKey(issuer);
            }

            await SetStatus("Saving Certificate Revocation List...");

            var crl = CertMaker.CreateCertificateRevocationList(file, issuercert, privateKey, lastUpdate.UtcDateTime, nextUpdate.UtcDateTime, items, cancel);

            byte[] encoded = crl.GetEncoded();
            File.WriteAllBytes(file, encoded);

            await SetStatus("Done.");
        }
        private async Task MakeCertificate(MakeCertArgs args, CancellationToken token)
        {
            Directory.CreateDirectory(CaDirectory);
            Directory.CreateDirectory(CertDirectory);

            await SetStatus("Checking for existing certificate");

            var safeFileName = Path.Combine(args.OutputPath, SafeFileName(args.Domains[0]));

            IStorageFile? file = null;
            await Dispatcher.UIThread.InvokeAsync(async () =>
            {
                var window = TopLevel.GetTopLevel(this) as Window;
                window.WindowStartupLocation = WindowStartupLocation.CenterScreen;
                window?.Activate();
                var topLevel = TopLevel.GetTopLevel(this);
                var folder = await topLevel.StorageProvider.TryGetFolderFromPathAsync(CertDirectory);
                file = await topLevel.StorageProvider.SaveFilePickerAsync(new FilePickerSaveOptions()
                {
                    Title = "Save Certificate",
                    SuggestedStartLocation = folder,
                    FileTypeChoices = args.SaveCerAndKey
                        ? new[]
                        {
                        new FilePickerFileType("Certificate Files") {
                            Patterns = IsWindows ? new[] { "*.key", "*.cer" } :
                                new[] { "*.key", "*.cer", "application/pkix-cert", "application/x-x509-ca-cert",
                                "application/x-pem-file", "application/x-pem-key", "application/pkcs8",
                                "application/pkcs8-encrypted" }
                        },
                        new FilePickerFileType("All Files") {
                            Patterns = IsWindows ? new[] { "*.*" } : new[] { "*.*", "*" }
                        }
                        }
                        : new[]
                        {
                        new FilePickerFileType("Certificate Files") {
                            Patterns = IsWindows ? new[] { "*.pfx" } :
                                new[] { "*.pfx", "application/x-pkcs12", "application/pkcs12" }
                        },
                        new FilePickerFileType("All Files")
                        {
                            Patterns = IsWindows ? new[] { "*.*" } : new[] { "*.*", "*" }
                        }
                        },
                    DefaultExtension = args.SaveCerAndKey ? "cer" : "pfx",
                    SuggestedFileName = Path.GetFileName(safeFileName) + (args.SaveCerAndKey ? ".cer" : ".pfx"),
                    ShowOverwritePrompt = true
                });
            });
            if (file == null)
            {
                await SetStatus("Operation cancelled.");
                return;
            }
            var result = file.TryGetLocalPath();
            if (!string.IsNullOrEmpty(result)) safeFileName = Path.Combine(Path.GetDirectoryName(result), Path.GetFileNameWithoutExtension(result));
            else return;

            if (args.SaveCerAndKey)
            {
                if (File.Exists(safeFileName + ".cer"))
                {
                    await SetStatus("File already exists: " + safeFileName + ".cer");
                    //if (!await Confirm("File Already Exists", $"File already exists: {safeFileName}.cer. Do you want to overwrite it?")) return;
                }
                if (File.Exists(safeFileName + ".key"))
                {
                    await SetStatus("File already exists: " + safeFileName + ".key");
                    //if (!await Confirm("File Already Exists", $"File already exists: {safeFileName}.key. Do you want to overwrite it?")) return;
                }
            }
            else
            {
                if (File.Exists(safeFileName + ".pfx"))
                {
                    await SetStatus("File already exists: " + safeFileName + ".pfx");
                    //if (!await Confirm("File Already Exists", $"File already exists: {safeFileName}.pfx. Do you want to overwrite it?")) return;
                }
            }

            if (token.IsCancellationRequested)
                return;

            await SetStatus("Generating certificate");

            CertificateBundle certBundle;
            if (args.Issuer == SelfSignedLabel)
            {
                certBundle = CertMaker.GetCertificateSignedBySelf(args);
            }
            else
            {
                // For simplicity, we currently only support issuers without passwords here.
                CertificateBundle issuerBundle = null!;
                var issuerFile = Path.Combine(CaDirectory, args.Issuer);
                if (issuerFile.EndsWith(".pfx", StringComparison.OrdinalIgnoreCase))
                {

                    try
                    {
                        issuerBundle = CertificateBundle.LoadFromPfxFile(issuerFile, null);
                    }
                    catch (Exception ex) { }
                    if (issuerBundle == null)
                    {
                        var password = await Dispatcher.UIThread.InvokeAsync(async () =>
                        {
                            var passwordPrompt = new PasswordPrompt();
                            passwordPrompt.PasswordLabel.Text = "Password for CA pfx:";
                            return await passwordPrompt.ShowDialog<string?>(this);
                        });
                        try
                        {
                            issuerBundle = CertificateBundle.LoadFromPfxFile(issuerFile, password);
                        }
                        catch (Exception ex)
                        {
                            await SetStatus($"Unable to load CA .pfx file (wrong password): {ex.Message}");
                            return;
                        }
                        if (issuerBundle == null)
                        {
                            await SetStatus("Unable to load CA .pfx file (wrong password).");
                            return;
                        }
                    }
                }
                else
                {
                    var cerFile = issuerFile.EndsWith(".key", StringComparison.OrdinalIgnoreCase)
                        ? Path.ChangeExtension(issuerFile, ".cer")
                        : null;
                    issuerBundle = CertificateBundle.LoadFromCerAndKeyFiles(cerFile, issuerFile);
                }

                certBundle = CertMaker.GetCertificateSignedByCA(args, issuerBundle);
            }

            if (token.IsCancellationRequested)
                return;

            await SetStatus("Saving certificate to disk");

            if (args.SaveCerAndKey)
            {
                File.WriteAllBytes(safeFileName + ".cer", certBundle.GetPublicCertAsCerFile());
                File.WriteAllBytes(safeFileName + ".key", certBundle.GetPrivateKeyAsKeyFile());
                if (LooksLikeCa(args))
                {
                    File.Copy(safeFileName + ".cer", Path.Combine(CaDirectory, Path.GetFileName(safeFileName + ".cer")));
                    File.Copy(safeFileName + ".key", Path.Combine(CaDirectory, Path.GetFileName(safeFileName + ".key")));
                }
            }
            else
            {
                var password = string.IsNullOrEmpty(args.Password) ? null : args.Password;
                File.WriteAllBytes(safeFileName + ".pfx", certBundle.GetPfx(password));
                if (LooksLikeCa(args))
                {
                    File.Copy(safeFileName + ".pfx", Path.Combine(CaDirectory, Path.GetFileName(safeFileName + ".pfx")));
                }
            }

            await SetStatus("Done.");
        }

        private string SafeFileName(string str)
        {
            var illegalChars = new HashSet<char>(new[]
            {
                '#','%','&','{','}','\\','<','>','*','?','/',' ','$','!','\'','"',':','@'
            });
            return new string(str.Select(c => illegalChars.Contains(c) ? '_' : c).ToArray());
        }

        private void StartProgress()
        {
            ProgressBar.IsIndeterminate = true;
        }

        private void StopProgress()
        {
            ProgressBar.IsIndeterminate = false;
            MakeCertButton.Content = MakeButtonText;
            MakeCertButton.IsEnabled = true;
            MakeCRLButton.Content = MakeCRLButtonText;
            MakeCRLButton.IsEnabled = true;
            PopulateIssuerDropdown(IssuerCombo);
            PopulateIssuerDropdown(CRLIssuerCombo);
        }

        private async Task SetStatus(string str)
        {
            await Dispatcher.UIThread.InvokeAsync(() => { StatusTextBlock.Text = str; });
        }

        private void WebServerPresetButton_OnClick(object? sender, RoutedEventArgs e)
        {
            ApplyWebServerPreset();
        }

        private void CaPresetButton_OnClick(object? sender, RoutedEventArgs e)
        {
            ApplyCaPreset();
        }

        private void ApplyWebServerPreset()
        {
            SetKeyUsageSelection(k => k.Key.EndsWith("(32)", StringComparison.Ordinal) || k.Key.EndsWith("(128)", StringComparison.Ordinal));
            SetExtendedKeyUsageSelection(k => k.Key == "Client Auth" || k.Key == "Server Auth");
            KeyStrengthComboBox.SelectedIndex = 1;
        }

        private void ApplyCaPreset()
        {
            SetKeyUsageSelection(k => k.Key.EndsWith("(2)", StringComparison.Ordinal) || k.Key.EndsWith("(4)", StringComparison.Ordinal));
            SetExtendedKeyUsageSelection(_ => false);
            KeyStrengthComboBox.SelectedIndex = 3;
        }

        private void SetKeyUsageSelection(Func<MultiSelectIntItem, bool> selector)
        {
            KeyUsageListBox.SelectedItems = KeyUsageOptions.Where(selector).ToList();
        }

        private void SetExtendedKeyUsageSelection(Func<MultiSelectKeyPurposeItem, bool> selector)
        {
            ExtendedKeyUsageListBox.SelectedItems = ExtendedKeyUsageOptions.Where(selector).ToList();
        }

        private void DeleteButton_Click(object? sender, RoutedEventArgs e)
        {
            var button = (Button)sender!;

            var item = button.DataContext as RevokeItem;

            if (item == null)
                return;

            RevokeItems.Load();
            RevokeItems.Remove(item.SerialNumber);
            RevokeItems.Save();
        }
    }
}