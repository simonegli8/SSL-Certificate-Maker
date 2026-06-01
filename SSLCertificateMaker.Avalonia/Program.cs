using Avalonia;
using Avalonia.Dialogs;
using System;
using System.Threading;
using System.Threading.Tasks;
using System.Runtime.CompilerServices;
using System.Diagnostics;

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
            if (args.Contains("-debug"))
            {
                Console.WriteLine("Wait for debugger to attach...");
                while (!Debugger.IsAttached) Thread.Sleep(200);
                Debugger.Break();
            }
#if  PackAsTool
            if (!GUIToolInstaller.Installer.Run(args, "SSL-Certificate-Maker", "cert", "SSL-Certificate-Maker, a cross platform GUI tool to manage self signed certificates."))
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
