using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Threading;
using Org.BouncyCastle.Asn1.X509;
using SSLCertificateMaker;

namespace SSLCertificateMaker.Avalonia
{
    public partial class MainWindow : Window
    {
        private const string SelfSignedLabel = "None (Self-Signed)";
        private const string MakeButtonText = "Make Certificate";
        private const string CancelButtonText = "Cancel";

        public static readonly string CaDirectory;
        public static readonly string CertDirectory;

        private CancellationTokenSource? _cts;

        private readonly MultiSelectIntItem[] _keyUsageOptions = new[]
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

        static MainWindow()
        {
            var exeDir = new DirectoryInfo(AppContext.BaseDirectory);
            CaDirectory = new DirectoryInfo(Path.Combine(exeDir.FullName, "CA")).FullName;
            CertDirectory = new DirectoryInfo(Path.Combine(exeDir.FullName, "CERT")).FullName;
            Directory.CreateDirectory(CaDirectory);
            Directory.CreateDirectory(CertDirectory);
        }

        public MainWindow()
        {
            InitializeComponent();

            InitializeUi();
        }

        private void InitializeUi()
        {
            Title += " " + typeof(MainWindow).Assembly.GetName().Version;

            // Dates
            ValidFromDatePicker.SelectedDate = DateTime.Today.AddYears(-10);
            ValidToDatePicker.SelectedDate = DateTime.Today.AddYears(500);

            // Key strength
            KeyStrengthComboBox.ItemsSource = new[] { "1024", "2048", "3072", "4096", "8192", "16384" };
            KeyStrengthComboBox.SelectedIndex = 1;

            // Output type
            OutputTypeComboBox.ItemsSource = new[] { ".pfx", ".cer, .key" };
            OutputTypeComboBox.SelectedIndex = 0;
            OutputTypeComboBox.SelectionChanged += OutputTypeComboBox_OnSelectionChanged;
            UpdatePasswordEnabled();

            // Key usage lists
            KeyUsageListBox.ItemsSource = _keyUsageOptions;
            ExtendedKeyUsageListBox.ItemsSource = ExtendedKeyUsageOptions;

            // Buttons
            MakeCertButton.Content = MakeButtonText;
            MakeCertButton.Click += MakeCertButton_OnClick;
            WebServerPresetButton.Click += WebServerPresetButton_OnClick;
            CaPresetButton.Click += CaPresetButton_OnClick;

            StatusTextBlock.Text = string.Empty;
            StopProgress();

            ApplyWebServerPreset();
            PopulateIssuerDropdown();
        }

        private void OutputTypeComboBox_OnSelectionChanged(object? sender, SelectionChangedEventArgs e)
        {
            UpdatePasswordEnabled();
        }

        private void UpdatePasswordEnabled()
        {
            if (OutputTypeComboBox.SelectedItem is string s)
            {
                PasswordTextBox.IsEnabled = s == ".pfx";
            }
        }

        private void PopulateIssuerDropdown()
        {
            var previouslySelected = IssuerCombo.SelectedItem as string;
            var items = new List<string> { SelfSignedLabel };

            foreach (var fi in new DirectoryInfo(CaDirectory).GetFiles())
            {
                if (string.Equals(fi.Extension, ".pfx", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(fi.Extension, ".key", StringComparison.OrdinalIgnoreCase))
                {
                    items.Add(fi.Name);
                }
            }

            items.Sort(StringComparer.OrdinalIgnoreCase);

            IssuerCombo.ItemsSource = items;
            if (!string.IsNullOrEmpty(previouslySelected) && items.Contains(previouslySelected))
            {
                IssuerCombo.SelectedItem = previouslySelected;
            }
            else
            {
                IssuerCombo.SelectedIndex = items.Count > 1 ? 1 : 0;
            }
        }

        private async void MakeCertButton_OnClick(object? sender, RoutedEventArgs e)
        {
            if (Equals(MakeCertButton.Content, MakeButtonText))
            {
                var domains = GetCleanDomainArray();
                if (domains.Length == 0)
                {
                    SetStatus("No domain names were entered (at least 'localhost' is recommended).");
                    return;
                }

                if (KeyStrengthComboBox.SelectedItem is not string keyStrengthStr ||
                    !int.TryParse(keyStrengthStr, out var keyStrength))
                {
                    SetStatus("Invalid key strength.");
                    return;
                }

                var validFrom = ValidFromDatePicker.SelectedDate ?? DateTime.Today;
                var validTo = ValidToDatePicker.SelectedDate ?? DateTime.Today.AddYears(1);

                var outputType = OutputTypeComboBox.SelectedItem as string ?? ".pfx";
                var issuer = IssuerCombo.SelectedItem as string ?? SelfSignedLabel;

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
                    extendedKeyUsage
                )
                {
                    OutputPath = CertDirectory
                };

                if (LooksLikeCa(args))
                {
                    // In WinForms this was user-confirmed; here we automatically place CAs into the CA folder.
                    args.OutputPath = CaDirectory;
                }

                MakeCertButton.Content = CancelButtonText;

                StartProgress();
                SetStatus("Generating certificate…");

                _cts = new CancellationTokenSource();

                try
                {
                    await Task.Run(() => MakeCertificate(args, _cts.Token));
                    if (_cts.IsCancellationRequested)
                    {
                        SetStatus("Aborted");
                    }
                    else
                    {
                        SetStatus(string.Empty);
                    }
                }
                catch (Exception ex)
                {
                    SetStatus("An error occurred while generating the certificate.");
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

        private void MakeCertificate(MakeCertArgs args, CancellationToken token)
        {
            Directory.CreateDirectory(CaDirectory);
            Directory.CreateDirectory(CertDirectory);

            SetStatus("Checking for existing certificate");

            var safeFileName = Path.Combine(args.OutputPath, SafeFileName(args.domains[0]));

            if (args.saveCerAndKey)
            {
                if (File.Exists(safeFileName + ".cer"))
                {
                    SetStatus("File already exists: " + safeFileName + ".cer");
                    return;
                }
                if (File.Exists(safeFileName + ".key"))
                {
                    SetStatus("File already exists: " + safeFileName + ".key");
                    return;
                }
            }
            else
            {
                if (File.Exists(safeFileName + ".pfx"))
                {
                    SetStatus("File already exists: " + safeFileName + ".pfx");
                    return;
                }
            }

            if (token.IsCancellationRequested)
                return;

            SetStatus("Generating certificate");

            CertificateBundle certBundle;
            if (args.issuer == SelfSignedLabel)
            {
                certBundle = CertMaker.GetCertificateSignedBySelf(args);
            }
            else
            {
                // For simplicity, we currently only support issuers without passwords here.
                CertificateBundle issuerBundle = null!;
                var issuerFile = Path.Combine(CaDirectory, args.issuer);
                if (issuerFile.EndsWith(".pfx", StringComparison.OrdinalIgnoreCase))
                {
                    issuerBundle = CertificateBundle.LoadFromPfxFile(issuerFile, null);
                    if (issuerBundle == null)
                    {
                        SetStatus("Unable to load CA .pfx file (password-protected pfx is not supported in this UI).");
                        return;
                    }
                }
                else
                {
                    var cerFile = issuerFile.EndsWith(".key", StringComparison.OrdinalIgnoreCase)
                        ? issuerFile[..^4] + ".cer"
                        : null;
                    issuerBundle = CertificateBundle.LoadFromCerAndKeyFiles(cerFile, issuerFile);
                }

                certBundle = CertMaker.GetCertificateSignedByCA(args, issuerBundle);
            }

            if (token.IsCancellationRequested)
                return;

            SetStatus("Saving certificate to disk");

            if (args.saveCerAndKey)
            {
                File.WriteAllBytes(safeFileName + ".cer", certBundle.GetPublicCertAsCerFile());
                File.WriteAllBytes(safeFileName + ".key", certBundle.GetPrivateKeyAsKeyFile());
            }
            else
            {
                var password = string.IsNullOrEmpty(args.password) ? null : args.password;
                File.WriteAllBytes(safeFileName + ".pfx", certBundle.GetPfx(password));
            }
        }

        private string SafeFileName(string str)
        {
            var illegalChars = new HashSet<char>(new[]
            {
                '#','%','&','{','}','\\','<','>','*','?','/',' ','$','!','\'','"'
                ,':','@'
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
            PopulateIssuerDropdown();
        }

        private void SetStatus(string str)
        {
            Dispatcher.UIThread.Post(() => { StatusTextBlock.Text = str; });
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
            KeyUsageListBox.SelectedItems = _keyUsageOptions.Where(selector).ToList();
        }

        private void SetExtendedKeyUsageSelection(Func<MultiSelectKeyPurposeItem, bool> selector)
        {
            ExtendedKeyUsageListBox.SelectedItems = ExtendedKeyUsageOptions.Where(selector).ToList();
        }
    }
}