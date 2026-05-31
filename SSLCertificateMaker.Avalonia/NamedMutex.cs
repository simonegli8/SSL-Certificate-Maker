using Org.BouncyCastle.Asn1.Tsp;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.Json.Serialization;
using System.Threading;

namespace SSLCertificateMaker.Avalonia
{
    public class NamedMutex : IDisposable
    {
        public static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);
        public const string MutexName = "Global\\sslcertmaker.lock";

        private static Mutex? mutex = null;
        private static object Lock = new();
        private bool hasHandle = false;
        [JsonIgnore]
        static Mutex Mutex
        {
            get
            {
                lock (Lock)
                {
                    if (mutex != null) return mutex;

                    const string MutexDiskPath = "/tmp/.dotnet/shm/global";
                    if ((OSInfo.IsLinux || OSInfo.IsMac) && !Directory.Exists(MutexDiskPath))
                    {
                        Directory.CreateDirectory(MutexDiskPath);
                        Unix.SetFilePermissions("/tmp/.dotnet", (UnixFileMode)0x1ff, true);
                    }

                    return mutex = new Mutex(false, MutexName);
                }
            }
        }
        public NamedMutex()
        {
            try
            {
                hasHandle = Mutex.WaitOne(Timeout);
                if (!hasHandle)
                {
                    throw new TimeoutException("Failed to acquire mutex.");
                }
            }
            catch (AbandonedMutexException)
            {
                hasHandle = true;
            }
        }
        public void Dispose()
        {
            if (hasHandle)
            {
                Mutex.ReleaseMutex();
                hasHandle = false;
            }
        }
    }
}
