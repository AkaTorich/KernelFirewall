using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;

namespace FirewallController.Services
{
    /// <summary>
    /// Global registry service for tracking unique process paths.
    /// Used to detect duplicate process names running from different paths.
    /// </summary>
    public class ProcessRegistryService
    {
        private static ProcessRegistryService? _instance;
        private static readonly object _lock = new object();

        // Dictionary: ProcessName -> List of unique paths
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
                        {
                            _instance = new ProcessRegistryService();
                        }
                    }
                }
                return _instance;
            }
        }

        /// <summary>
        /// Register a process with its path. Only adds new paths, never removes.
        /// </summary>
        /// <param name="processName">Process name (without .exe)</param>
        /// <param name="path">Full path to the process executable</param>
        public void RegisterProcess(string processName, string path)
        {
            if (string.IsNullOrWhiteSpace(processName) || string.IsNullOrWhiteSpace(path))
                return;

            // Normalize process name (remove .exe if present)
            var normalizedName = processName.Replace(".exe", "", StringComparison.OrdinalIgnoreCase);

            _processRegistry.AddOrUpdate(
                normalizedName,
                new HashSet<string>(StringComparer.OrdinalIgnoreCase) { path },
                (key, existingSet) =>
                {
                    lock (existingSet)
                    {
                        existingSet.Add(path);
                    }
                    return existingSet;
                });
        }

        /// <summary>
        /// Check if a process has multiple different paths registered.
        /// </summary>
        /// <param name="processName">Process name (without .exe)</param>
        /// <param name="currentPath">Current path to check</param>
        /// <returns>True if there are other paths registered for this process name</returns>
        public bool IsDuplicate(string processName, string currentPath)
        {
            if (string.IsNullOrWhiteSpace(processName) || string.IsNullOrWhiteSpace(currentPath))
                return false;

            var normalizedName = processName.Replace(".exe", "", StringComparison.OrdinalIgnoreCase);

            if (_processRegistry.TryGetValue(normalizedName, out var paths))
            {
                lock (paths)
                {
                    // If there's only one path and it's the same as current - NOT a duplicate
                    if (paths.Count == 1 && paths.Contains(currentPath))
                        return false;

                    // If there are multiple paths - it's a duplicate
                    if (paths.Count > 1)
                        return true;

                    // If there's one path but it's different from current - will become duplicate
                    if (paths.Count == 1 && !paths.Contains(currentPath))
                        return true;
                }
            }

            return false;
        }

        /// <summary>
        /// Get all registered paths for a process name.
        /// </summary>
        public List<string> GetRegisteredPaths(string processName)
        {
            if (string.IsNullOrWhiteSpace(processName))
                return new List<string>();

            var normalizedName = processName.Replace(".exe", "", StringComparison.OrdinalIgnoreCase);

            if (_processRegistry.TryGetValue(normalizedName, out var paths))
            {
                lock (paths)
                {
                    return paths.ToList();
                }
            }

            return new List<string>();
        }

        /// <summary>
        /// Get count of unique paths for a process name.
        /// </summary>
        public int GetPathCount(string processName)
        {
            if (string.IsNullOrWhiteSpace(processName))
                return 0;

            var normalizedName = processName.Replace(".exe", "", StringComparison.OrdinalIgnoreCase);

            if (_processRegistry.TryGetValue(normalizedName, out var paths))
            {
                lock (paths)
                {
                    return paths.Count;
                }
            }

            return 0;
        }

        /// <summary>
        /// Clear all registered processes (use with caution).
        /// </summary>
        public void Clear()
        {
            _processRegistry.Clear();
        }

        /// <summary>
        /// Get total number of unique process names registered.
        /// </summary>
        public int GetTotalProcessCount()
        {
            return _processRegistry.Count;
        }

        /// <summary>
        /// Get statistics about the registry.
        /// </summary>
        public string GetStatistics()
        {
            int totalProcesses = _processRegistry.Count;
            int duplicates = _processRegistry.Count(kvp =>
            {
                lock (kvp.Value)
                {
                    return kvp.Value.Count > 1;
                }
            });

            return $"Процессов: {totalProcesses}, с дубликатами: {duplicates}";
        }
    }
}
