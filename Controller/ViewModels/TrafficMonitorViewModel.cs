using System;
using System.Collections.ObjectModel;
using System.Windows;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using FirewallController.Models;
using FirewallController.Services;

namespace FirewallController.ViewModels
{
    public partial class TrafficMonitorViewModel : ObservableObject
    {
        private readonly DriverService _driverService;
        private EtwService? _etwService;
        private readonly string _processFilter;

        [ObservableProperty] private ObservableCollection<TrafficEntry> _trafficEntries = new();
        [ObservableProperty] private TrafficEntry? _selectedEntry;
        [ObservableProperty] private TrafficEntry? _frozenEntry; // Frozen details - won't disappear when item removed
        [ObservableProperty] private bool _isMonitoring = true;
        [ObservableProperty] private bool _autoScroll = true;
        [ObservableProperty] private string _filterText = "";
        [ObservableProperty] private bool _showBlocked = true;
        [ObservableProperty] private bool _showAllowed = true;
        [ObservableProperty] private bool _showTcp = true;
        [ObservableProperty] private bool _showUdp = true;
        [ObservableProperty] private string _statusText = "Ожидание...";
        [ObservableProperty] private int _eventCount = 0;

        public TrafficMonitorViewModel(DriverService driverService, string processFilter = "")
        {
            _driverService = driverService;
            _processFilter = processFilter.ToLower();
        }

        public void Start()
        {
            try
            {
                LogWindow.Log($"TrafficMonitor: Starting, filter='{_processFilter}'");

                _driverService.SetMonitoring(true);

                _etwService = new EtwService();
                _etwService.OnNetworkEvent += OnEtwNetworkEvent;

                if (_etwService.Start())
                {
                    StatusText = "🟢 ETW активен";
                    LogWindow.Log("TrafficMonitor: ETW started");
                }
                else
                {
                    StatusText = "🔴 ETW недоступен";
                    LogWindow.Log("TrafficMonitor: ETW failed");
                }
            }
            catch (Exception ex)
            {
                StatusText = $"🔴 Ошибка: {ex.Message}";
                LogWindow.Log($"TrafficMonitor: Start error - {ex.Message}");
            }
        }

        public void Cleanup()
        {
            try
            {
                if (_etwService != null)
                {
                    _etwService.OnNetworkEvent -= OnEtwNetworkEvent;
                    _etwService.Stop();
                    _etwService.Dispose();
                    _etwService = null;
                }
                StatusText = "⚪ Остановлен";
            }
            catch (Exception ex)
            {
                LogWindow.Log($"TrafficMonitor: Cleanup error - {ex.Message}");
            }
        }

        private void OnEtwNetworkEvent(TrafficEntry entry)
        {
            try
            {
                if (!IsMonitoring) return;

                // Apply filters
                if (!PassesFilter(entry)) return;

                // Add to collection on UI thread
                Application.Current?.Dispatcher.BeginInvoke(() =>
                {
                    try
                    {
                        TrafficEntries.Add(entry);
                        EventCount = TrafficEntries.Count;

                        // Limit entries
                        while (TrafficEntries.Count > 1000)
                        {
                            TrafficEntries.RemoveAt(0);
                        }
                    }
                    catch { }
                });
            }
            catch { }
        }

        private bool PassesFilter(TrafficEntry entry)
        {
            try
            {
                // Process filter from dialog
                if (!string.IsNullOrEmpty(_processFilter))
                {
                    var processName = entry.ProcessName?.ToLower() ?? "";
                    var filterWithoutExt = _processFilter.Replace(".exe", "");
                    if (!processName.Contains(_processFilter) && !processName.Contains(filterWithoutExt))
                        return false;
                }
                
                if (!ShowBlocked && entry.WasBlocked) return false;
                if (!ShowAllowed && !entry.WasBlocked) return false;
                if (!ShowTcp && entry.Protocol == ProtocolType.TCP) return false;
                if (!ShowUdp && entry.Protocol == ProtocolType.UDP) return false;
                
                if (!string.IsNullOrWhiteSpace(FilterText))
                {
                    var filter = FilterText.ToLower();
                    var processName = entry.ProcessName?.ToLower() ?? "";
                    if (!processName.Contains(filter) &&
                        !entry.LocalAddress.Contains(filter) &&
                        !entry.RemoteAddress.Contains(filter))
                        return false;
                }
                
                return true;
            }
            catch
            {
                return true;
            }
        }
        
        private void ReapplyFilters()
        {
            try
            {
                var allEntries = new TrafficEntry[TrafficEntries.Count];
                TrafficEntries.CopyTo(allEntries, 0);
                
                TrafficEntries.Clear();
                foreach (var entry in allEntries)
                {
                    if (PassesFilter(entry))
                    {
                        TrafficEntries.Add(entry);
                    }
                }
                EventCount = TrafficEntries.Count;
            }
            catch { }
        }

        [RelayCommand]
        private void ClearTraffic()
        {
            _etwService?.ClearQueue();
            TrafficEntries.Clear();
            EventCount = 0;
        }

        [RelayCommand]
        private void ToggleMonitoring()
        {
            IsMonitoring = !IsMonitoring;
            _driverService.SetMonitoring(IsMonitoring);
            StatusText = IsMonitoring ? "🟢 ETW активен" : "⏸️ Пауза";
        }

        partial void OnFilterTextChanged(string value) => ReapplyFilters();
        partial void OnShowBlockedChanged(bool value) => ReapplyFilters();
        partial void OnShowAllowedChanged(bool value) => ReapplyFilters();
        partial void OnShowTcpChanged(bool value) => ReapplyFilters();
        partial void OnShowUdpChanged(bool value) => ReapplyFilters();

        // Freeze packet details when selected - they won't disappear when packet removed from list
        partial void OnSelectedEntryChanged(TrafficEntry? value)
        {
            if (value != null)
            {
                FrozenEntry = value;
            }
        }
    }
}
