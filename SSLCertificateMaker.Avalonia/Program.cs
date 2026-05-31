using Avalonia;
using Avalonia.Dialogs;
using System;
using System.Threading.Tasks;
using System.Runtime.CompilerServices;

namespace SSLCertificateMaker.Avalonia
{
    internal class Program
    {
        // Initialization code. Don't use any Avalonia, third-party APIs or any
        // SynchronizationContext-reliant code before AppMain is called: things aren't initialized
        // yet and stuff might break.
        [STAThread]
        public static async Task Main(string[] args)
        {
#if  PackAsTool
            var assembly = System.Reflection.Assembly.GetExecutingAssembly();
            var version = assembly.GetName().Version.ToString(3); ;
            if (!GUIToolInstaller.Installer.Run(args, "SSL-Certificate-Maker", "cert", version, "SSL-Certificate-Maker, a cross platform GUI tool to manage self signed certificates."))
            {
                BuildAvaloniaApp()
                .StartWithClassicDesktopLifetime(args);
            }
#else
                BuildAvaloniaApp()
                .StartWithClassicDesktopLifetime(args);
#endif
        }
        // Avalonia configuration, don't remove; also used by visual designer.
        public static AppBuilder BuildAvaloniaApp()
            => AppBuilder.Configure<App>()
                .UsePlatformDetect()
                .WithInterFont()
                .LogToTrace();
    }
}
