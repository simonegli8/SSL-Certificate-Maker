using Avalonia;
using Avalonia.Controls;
using Avalonia.Markup.Xaml;

namespace SSLCertificateMaker.Avalonia;

public partial class PasswordPrompt : Window
{
    public PasswordPrompt()
    {
        InitializeComponent();

        OkButton.Click += (_, _) => Close(Password.Text);
        CancelButton.Click += (_, _) => Close(null);
    }
}