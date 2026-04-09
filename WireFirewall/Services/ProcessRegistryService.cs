using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;

namespace HackerFirewall.Services
{
    public class ProcessRegistryService
    {
        private static ProcessRegistryService _instance;
        private static readonly object _lock = new object();

        private readonly ConcurrentDictionary<string, HashSet<string>> _processRegistry;

        private ProcessRegistryService()
        {
            _processRegistry = new ConcurrentDictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase);
        }

        public static ProcessRegistryService Instance
        {
            get
            {
                if (_instance == null)
                {
                    lock (_lock)
                    {
                        if (_instance == null)
                            _instance = new ProcessRegistryService();
                    }
                }
                return _instance;
            }
        }

        public void RegisterProcess(string processName, string path)
        {
            if (string.IsNullOrWhiteSpace(processName) || string.IsNullOrWhiteSpace(path))
                return;

            var normalizedName = Regex.Replace(processName, @"\.exe$", "", RegexOptions.IgnoreCase);

            _processRegistry.AddOrUpdate(
                normalizedName,
                new HashSet<string>(StringComparer.OrdinalIgnoreCase) { path },
                (key, existingSet) =>
                {
                    lock (existingSet) { existingSet.Add(path); }
                    return existingSet;
                });
        }

        public bool IsDuplicate(string processName, string currentPath)
        {
            if (string.IsNullOrWhiteSpace(processName) || string.IsNullOrWhiteSpace(currentPath))
                return false;

            var normalizedName = Regex.Replace(processName, @"\.exe$", "", RegexOptions.IgnoreCase);

            if (_processRegistry.TryGetValue(normalizedName, out var paths))
            {
                lock (paths)
                {
                    if (paths.Count == 1 && paths.Contains(currentPath)) return false;
                    if (paths.Count > 1) return true;
                    if (paths.Count == 1 && !paths.Contains(currentPath)) return true;
                }
            }
            return false;
        }

        public List<string> GetRegisteredPaths(string processName)
        {
            if (string.IsNullOrWhiteSpace(processName))
                return new List<string>();

            var normalizedName = Regex.Replace(processName, @"\.exe$", "", RegexOptions.IgnoreCase);

            if (_processRegistry.TryGetValue(normalizedName, out var paths))
            {
                lock (paths) { return paths.ToList(); }
            }
            return new List<string>();
        }

        public int GetPathCount(string processName)
        {
            if (string.IsNullOrWhiteSpace(processName)) return 0;

            var normalizedName = Regex.Replace(processName, @"\.exe$", "", RegexOptions.IgnoreCase);

            if (_processRegistry.TryGetValue(normalizedName, out var paths))
            {
                lock (paths) { return paths.Count; }
            }
            return 0;
        }

        public void Clear() => _processRegistry.Clear();

        public int GetTotalProcessCount() => _processRegistry.Count;

        public string GetStatistics()
        {
            int totalProcesses = _processRegistry.Count;
            int duplicates = _processRegistry.Count(kvp =>
            {
                lock (kvp.Value) { return kvp.Value.Count > 1; }
            });
            return $"Processes: {totalProcesses}, duplicates: {duplicates}";
        }
    }
}
