using Avalonia;
using Avalonia.Controls;
using Avalonia.Markup.Xaml;
using Org.BouncyCastle.Asn1.X509;
using System.Collections.ObjectModel;
using System.Linq;
using SSLCertificateMaker.Library;

namespace SSLCertificateMaker.Avalonia;

public partial class CrlReasonPrompt : Window
{
    static ObservableCollection<ReasonItem> Reasons => CertMaker.Reasons;

    public static readonly StyledProperty<ReasonItem> SelectedReasonProperty =
        AvaloniaProperty.Register<CrlReasonPrompt, ReasonItem>(nameof(SelectedReason),
            new ReasonItem("Unspecified", CrlReason.Unspecified));

    public ReasonItem SelectedReason
    {
        get => GetValue(SelectedReasonProperty);
        set => SetValue(SelectedReasonProperty, value);
    }

    public static int? ToInt(string name) => CertMaker.ToInt(name);
    public static string ToString(int? reason) => CertMaker.ToString(reason);
    public CrlReasonPrompt()
    {
        InitializeComponent();
        DataContext = this;
        Reason.ItemsSource = Reasons;
        OkButton.Click += (_, _) => Close(SelectedReason.Reason);
        CancelButton.Click += (_, _) => Close(CrlReason.Unspecified);
    }
}