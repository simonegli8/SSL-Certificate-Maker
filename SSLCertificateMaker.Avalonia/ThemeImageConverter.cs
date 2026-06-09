using Avalonia;
using Avalonia.Data.Converters;
using Avalonia.Media.Imaging;
using Avalonia.Platform;
using Avalonia.Styling;
using System;
using System.Globalization;


namespace SSLCertificateMaker.Avalonia;

public class ThemeToDeleteIconConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        var theme = Application.Current?.ActualThemeVariant;
        return theme == ThemeVariant.Dark
            ? new Bitmap(AssetLoader.Open(new Uri("avares://SSLCertificateMaker/Resources/delete-white.png")))
            : new Bitmap(AssetLoader.Open(new Uri("avares://SSLCertificateMaker/Resources/delete.png")));
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => throw new NotSupportedException();
}