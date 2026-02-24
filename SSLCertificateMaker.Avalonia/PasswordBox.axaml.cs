using Avalonia;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Interactivity;
using Avalonia.Markup.Xaml;
using Avalonia.Data;

namespace SSLCertificateMaker.Avalonia;

public partial class PasswordBox : UserControl
{
    public bool IsRevealed = false;

    public PasswordBox()
    {
        InitializeComponent();
        PART_RevealButton.Click += RevealButton_Click;
    }

    private void RevealButton_Click(object? sender, RoutedEventArgs e)
    {
        IsRevealed = !IsRevealed;
        //PART_TextBox.RevealPassword = IsRevealed = IsRevealed;
        PART_TextBox.PasswordChar = IsRevealed ? '\0' : PasswordChar;
    }


	protected override void OnLoaded(RoutedEventArgs e)
	{
		base.OnLoaded(e);
	}
    public static readonly StyledProperty<string> TextProperty =
        AvaloniaProperty.Register<PasswordBox, string>(nameof(Text), defaultBindingMode: BindingMode.TwoWay);

    public string Text
    {
        get => GetValue(TextProperty);
        set => SetValue(TextProperty, value);
    }

    public static readonly StyledProperty<char> PasswordCharProperty =
        AvaloniaProperty.Register<PasswordBox, char>(nameof(PasswordChar), '●');

    public char PasswordChar
    {
        get => GetValue(PasswordCharProperty);
        set => SetValue(PasswordCharProperty, value);
    }

    public static readonly StyledProperty<string> WatermarkProperty =
        AvaloniaProperty.Register<PasswordBox, string>(nameof(Watermark));

    public string Watermark
    {
        get => GetValue(WatermarkProperty);
        set => SetValue(WatermarkProperty, value);
    }
}