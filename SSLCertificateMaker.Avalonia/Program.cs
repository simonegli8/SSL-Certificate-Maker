using Avalonia;
using Avalonia.Dialogs;
using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

namespace SSLCertificateMaker.Avalonia;

internal class Program
{
    // Initialization code. Don't use any Avalonia, third-party APIs or any
    // SynchronizationContext-reliant code before AppMain is called: things aren't initialized
    // yet and stuff might break.
    [STAThread]
    public static void Main(string[] args)
    {
        if (OSInfo.IsWindows)
        {
            try
            {
                if (!HasConsole()) AttachConsole();
            }
            catch { }
        }
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

    [DllImport("kernel32.dll")]
    static extern IntPtr GetConsoleWindow();

    static bool HasConsole()
    {
        return GetConsoleWindow() != IntPtr.Zero;
    }

    const int ATTACH_PARENT_PROCESS = -1;

    [DllImport("kernel32.dll")]
    static extern bool AttachConsole(int dwProcessId);

    static bool AttachConsole() => AttachConsole(ATTACH_PARENT_PROCESS);
}