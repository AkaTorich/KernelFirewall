using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Runtime.InteropServices;
using System.Text;
using FirewallController.Models;

namespace FirewallController.Services
{
    public class ProcessService
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool QueryFullProcessImageName(IntPtr hProcess, int dwFlags, StringBuilder lpExeName, ref int lpdwSize);

        private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
        private const uint PROCESS_QUERY_INFORMATION = 0x0400;

        public bool ShowSystemProcesses { get; set; } = false;
        public bool ShowDuplicatePaths { get; set; } = true;

        public List<ProcessInfo> GetRunningProcesses()
        {
            var processes = new List<ProcessInfo>();
            var seenPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            foreach (var process in Process.GetProcesses())
            {
                try
                {
                    // Skip system idle process (PID 0)
                    if (process.Id == 0)
                        continue;

                    var path = GetProcessPath(process.Id);

                    // If can't get path, try MainModule (requires elevation for some)
                    if (string.IsNullOrEmpty(path))
                    {
                        try
                        {
                            path = process.MainModule?.FileName;
                        }
                        catch
                        {
                            // Can't access - try process name
                        }
                    }

                    // If still no path, try WMI (works better with admin rights)
                    if (string.IsNullOrEmpty(path))
                    {
                        path = GetProcessPathFromWmi(process.Id);
                    }

                    // If still no path, use PID as identifier for blocking
                    if (string.IsNullOrEmpty(path))
                    {
                        if (ShowSystemProcesses)
                        {
                            // Use PID as path identifier - will be blocked by PID in driver
                            path = $"PID:{process.Id}";
                        }
                        else
                        {
                            continue; // Skip if can't get path and system processes are hidden
                        }
                    }

                    // Filter system processes if disabled
                    if (!ShowSystemProcesses)
                    {
                        if (path.StartsWith(@"C:\Windows\System32", StringComparison.OrdinalIgnoreCase) ||
                            path.StartsWith(@"C:\Windows\SysWOW64", StringComparison.OrdinalIgnoreCase) ||
                            path.StartsWith(@"C:\Windows\SystemApps", StringComparison.OrdinalIgnoreCase) ||
                            path.Equals("[System]", StringComparison.OrdinalIgnoreCase))
                            continue;
                    }

                    // Skip duplicates if disabled
                    if (!ShowDuplicatePaths && seenPaths.Contains(path))
                        continue;

                    seenPaths.Add(path);

                    processes.Add(new ProcessInfo
                    {
                        ProcessId = (uint)process.Id,
                        ProcessName = process.ProcessName,
                        ExecutablePath = path,
                        IsSelected = false
                    });
                }
                catch
                {
                    // Skip processes we can't access
                }
            }

            return processes.OrderBy(p => p.ProcessName).ToList();
        }

        public List<ProcessInfo> GetAllProcesses()
        {
            var processes = new List<ProcessInfo>();

            foreach (var process in Process.GetProcesses())
            {
                try
                {
                    if (process.Id == 0) continue;

                    var path = GetProcessPath(process.Id);
                    if (string.IsNullOrEmpty(path))
                    {
                        try { path = process.MainModule?.FileName; } catch { }
                    }

                    processes.Add(new ProcessInfo
                    {
                        ProcessId = (uint)process.Id,
                        ProcessName = process.ProcessName,
                        ExecutablePath = path ?? "(недоступно)",
                        IsSelected = false
                    });
                }
                catch
                {
                    // Skip
                }
            }

            return processes.OrderBy(p => p.ProcessName).ToList();
        }

        public string? GetProcessPath(int processId)
        {
            // Try with limited information first (works for most processes)
            var handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, processId);
            if (handle != IntPtr.Zero)
            {
                try
                {
                    var buffer = new StringBuilder(1024);
                    int size = buffer.Capacity;
                    if (QueryFullProcessImageName(handle, 0, buffer, ref size))
                    {
                        return buffer.ToString();
                    }
                }
                finally
                {
                    CloseHandle(handle);
                }
            }

            // Try with full information (requires admin rights for system processes)
            handle = OpenProcess(PROCESS_QUERY_INFORMATION, false, processId);
            if (handle != IntPtr.Zero)
            {
                try
                {
                    var buffer = new StringBuilder(1024);
                    int size = buffer.Capacity;
                    if (QueryFullProcessImageName(handle, 0, buffer, ref size))
                    {
                        return buffer.ToString();
                    }
                }
                finally
                {
                    CloseHandle(handle);
                }
            }

            return null;
        }

        private string? GetProcessPathFromWmi(int processId)
        {
            try
            {
                using (var searcher = new ManagementObjectSearcher(
                    $"SELECT ExecutablePath FROM Win32_Process WHERE ProcessId = {processId}"))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        var path = obj["ExecutablePath"]?.ToString();
                        if (!string.IsNullOrEmpty(path))
                        {
                            return path;
                        }
                    }
                }
            }
            catch
            {
                // WMI might not be available or accessible
            }

            return null;
        }

        public string GetProcessNameFromPath(string path)
        {
            return Path.GetFileNameWithoutExtension(path);
        }
    }
}
