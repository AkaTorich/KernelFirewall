using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.Windows;
using System.Windows.Input;
using HackerFirewall.Infrastructure;
using HackerFirewall.Models;
using HackerFirewall.Services;

namespace HackerFirewall.ViewModels
{
    public class TrafficMonitorViewModel : ViewModelBase
    {
        private readonly DriverService _driverService;
        private EtwService _etwService;
        private readonly string _processFilter;

        private ObservableCollection<TrafficEntry> _trafficEntries = new ObservableCollection<TrafficEntry>();
        public ObservableCollection<TrafficEntry> TrafficEntries { get => _trafficEntries; set => SetProperty(ref _trafficEntries, value); }

        private TrafficEntry _selectedEntry;
        public TrafficEntry SelectedEntry
        {
            get => _selectedEntry;
            set
            {
                if (SetProperty(ref _selectedEntry, value) && value != null)
                    FrozenEntry = value;
            }
        }

        private TrafficEntry _frozenEntry;
        public TrafficEntry FrozenEntry { get => _frozenEntry; set => SetProperty(ref _frozenEntry, value); }

        private bool _isMonitoring = true;
        public bool IsMonitoring { get => _isMonitoring; set => SetProperty(ref _isMonitoring, value); }

        private bool _autoScroll = true;
        public bool AutoScroll { get => _autoScroll; set => SetProperty(ref _autoScroll, value); }

        private string _filterText = "";
        public string FilterText
        {
            get => _filterText;
            set { if (SetProperty(ref _filterText, value)) ReapplyFilters(); }
        }

        private bool _showBlocked = true;
        public bool ShowBlocked
        {
            get => _showBlocked;
            set { if (SetProperty(ref _showBlocked, value)) ReapplyFilters(); }
        }

        private bool _showAllowed = true;
        public bool ShowAllowed
        {
            get => _showAllowed;
            set { if (SetProperty(ref _showAllowed, value)) ReapplyFilters(); }
        }

        private bool _showTcp = true;
        public bool ShowTcp
        {
            get => _showTcp;
            set { if (SetProperty(ref _showTcp, value)) ReapplyFilters(); }
        }

        private bool _showUdp = true;
        public bool ShowUdp
        {
            get => _showUdp;
            set { if (SetProperty(ref _showUdp, value)) ReapplyFilters(); }
        }

        private string _statusText = "[ WAITING... ]";
        public string StatusText { get => _statusText; set => SetProperty(ref _statusText, value); }

        private int _eventCount = 0;
        public int EventCount { get => _eventCount; set => SetProperty(ref _eventCount, value); }

        public ICommand ClearTrafficCommand { get; }
        public ICommand ToggleMonitoringCommand { get; }

        public TrafficMonitorViewModel(DriverService driverService, string processFilter = "")
        {
            _driverService = driverService;
            _processFilter = (processFilter ?? "").ToLower();

            ClearTrafficCommand = new RelayCommand(ClearTrafficExecute);
            ToggleMonitoringCommand = new RelayCommand(ToggleMonitoringExecute);
        }

        public void Start()
        {
            try
            {
                LogService.Log($"TrafficMonitor: Starting, filter='{_processFilter}'");
                _driverService.SetMonitoring(true);
                _etwService = new EtwService();
                _etwService.OnNetworkEvent += OnEtwNetworkEvent;

                if (_etwService.Start())
                {
                    StatusText = "[ ETW ACTIVE ]";
                    LogService.Log("TrafficMonitor: ETW started");
                }
                else
                {
                    StatusText = "[ ETW FAILED ]";
                    LogService.Log("TrafficMonitor: ETW failed");
                }
            }
            catch (Exception ex)
            {
                StatusText = $"[ ERROR: {ex.Message} ]";
                LogService.Log($"TrafficMonitor: Start error - {ex.Message}");
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
                StatusText = "[ STOPPED ]";
            }
            catch (Exception ex)
            {
                LogService.Log($"TrafficMonitor: Cleanup error - {ex.Message}");
            }
        }

        private void OnEtwNetworkEvent(TrafficEntry entry)
        {
            try
            {
                if (!IsMonitoring) return;
                if (!PassesFilter(entry)) return;

                Application.Current?.Dispatcher.BeginInvoke(new Action(() =>
                {
                    try
                    {
                        TrafficEntries.Add(entry);
                        EventCount = TrafficEntries.Count;
                        while (TrafficEntries.Count > 1000)
                            TrafficEntries.RemoveAt(0);
                    }
                    catch { }
                }));
            }
            catch { }
        }

        private bool PassesFilter(TrafficEntry entry)
        {
            try
            {
                if (!string.IsNullOrEmpty(_processFilter))
                {
                    var processName = (entry.ProcessName ?? "").ToLower();
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
                    var processName = (entry.ProcessName ?? "").ToLower();
                    if (!processName.Contains(filter) &&
                        !entry.LocalAddress.Contains(filter) &&
                        !entry.RemoteAddress.Contains(filter))
                        return false;
                }
                return true;
            }
            catch { return true; }
        }

        private void ReapplyFilters()
        {
            try
            {
                var allEntries = TrafficEntries.ToArray();
                TrafficEntries.Clear();
                foreach (var entry in allEntries)
                {
                    if (PassesFilter(entry))
                        TrafficEntries.Add(entry);
                }
                EventCount = TrafficEntries.Count;
            }
            catch { }
        }

        private void ClearTrafficExecute()
        {
            _etwService?.ClearQueue();
            TrafficEntries.Clear();
            EventCount = 0;
        }

        private void ToggleMonitoringExecute()
        {
            IsMonitoring = !IsMonitoring;
            _driverService.SetMonitoring(IsMonitoring);
            StatusText = IsMonitoring ? "[ ETW ACTIVE ]" : "[ PAUSED ]";
        }
    }
}
