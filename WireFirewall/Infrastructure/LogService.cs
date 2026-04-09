using System;
using System.Diagnostics;

namespace HackerFirewall.Infrastructure
{
    public static class LogService
    {
        public static event Action<string> OnLog;

        public static void Log(string message)
        {
            try
            {
                var timestamp = DateTime.Now.ToString("HH:mm:ss.fff");
                var line = $"[{timestamp}] {message}";
                Debug.WriteLine(line);
                OnLog?.Invoke(line);
            }
            catch { }
        }
    }
}
