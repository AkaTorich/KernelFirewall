using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.Windows;
using System.Windows.Input;
using System.Windows.Threading;
using HackerFirewall.Infrastructure;
using HackerFirewall.Models;
using HackerFirewall.Services;

namespace HackerFirewall.ViewModels
{
    public class MainViewModel : ViewModelBase
    {
        private readonly DriverService _driverService;
        private readonly ProcessService _processService;
        private readonly DispatcherTimer _statusTimer;

        public DriverService DriverService => _driverService;

        private bool _isConnected;
        public bool IsConnected { get => _isConnected; set => SetProperty(ref _isConnected, value); }

        private bool _isFirewallEnabled;
        public bool IsFirewallEnabled { get => _isFirewallEnabled; set => SetProperty(ref _isFirewallEnabled, value); }

        private uint _packetsBlocked;
        public uint PacketsBlocked { get => _packetsBlocked; set => SetProperty(ref _packetsBlocked, value); }

        private uint _packetsAllowed;
        public uint PacketsAllowed { get => _packetsAllowed; set => SetProperty(ref _packetsAllowed, value); }

        private string _statusText = "[OFFLINE]";
        public string StatusText { get => _statusText; set => SetProperty(ref _statusText, value); }

        private ObservableCollection<ProcessInfo> _runningProcesses = new ObservableCollection<ProcessInfo>();
        public ObservableCollection<ProcessInfo> RunningProcesses { get => _runningProcesses; set => SetProperty(ref _runningProcesses, value); }

        private ObservableCollection<BlockedApp> _blockedApps = new ObservableCollection<BlockedApp>();
        public ObservableCollection<BlockedApp> BlockedApps { get => _blockedApps; set => SetProperty(ref _blockedApps, value); }

        private ObservableCollection<FirewallRule> _rules = new ObservableCollection<FirewallRule>();
        public ObservableCollection<FirewallRule> Rules { get => _rules; set => SetProperty(ref _rules, value); }

        private ProcessInfo _selectedProcess;
        public ProcessInfo SelectedProcess { get => _selectedProcess; set => SetProperty(ref _selectedProcess, value); }

        private BlockedApp _selectedBlockedApp;
        public BlockedApp SelectedBlockedApp { get => _selectedBlockedApp; set => SetProperty(ref _selectedBlockedApp, value); }

        private FirewallRule _selectedRule;
        public FirewallRule SelectedRule { get => _selectedRule; set => SetProperty(ref _selectedRule, value); }

        private string _newRulePath = "";
        public string NewRulePath { get => _newRulePath; set => SetProperty(ref _newRulePath, value); }

        private FirewallAction _newRuleAction = FirewallAction.Block;
        public FirewallAction NewRuleAction { get => _newRuleAction; set => SetProperty(ref _newRuleAction, value); }

        private TrafficDirection _newRuleDirection = TrafficDirection.Output;
        public TrafficDirection NewRuleDirection { get => _newRuleDirection; set => SetProperty(ref _newRuleDirection, value); }

        private string _newRulePorts = "";
        public string NewRulePorts { get => _newRulePorts; set => SetProperty(ref _newRulePorts, value); }

        private string _newRuleIps = "";
        public string NewRuleIps { get => _newRuleIps; set => SetProperty(ref _newRuleIps, value); }

        private bool _showSystemProcesses = false;
        public bool ShowSystemProcesses
        {
            get => _showSystemProcesses;
            set
            {
                if (SetProperty(ref _showSystemProcesses, value))
                {
                    _processService.ShowSystemProcesses = value;
                    RefreshProcessesExecute();
                }
            }
        }

        private bool _showAllInstances = true;
        public bool ShowAllInstances
        {
            get => _showAllInstances;
            set
            {
                if (SetProperty(ref _showAllInstances, value))
                {
                    _processService.ShowDuplicatePaths = value;
                    RefreshProcessesExecute();
                }
            }
        }

        // Commands
        public ICommand ConnectToDriverCommand { get; }
        public ICommand ToggleFirewallCommand { get; }
        public ICommand RefreshProcessesCommand { get; }
        public ICommand BlockSelectedProcessCommand { get; }
        public ICommand BlockSelectedProcessesCommand { get; }
        public ICommand UnblockSelectedAppCommand { get; }
        public ICommand UnblockAllAppsCommand { get; }
        public ICommand AddRuleCommand { get; }
        public ICommand RemoveSelectedRuleCommand { get; }
        public ICommand ClearAllRulesCommand { get; }
        public ICommand UseSelectedProcessPathCommand { get; }
        public ICommand SelectAllProcessesCommand { get; }
        public ICommand DeselectAllProcessesCommand { get; }
        public ICommand SaveSessionCommand { get; }
        public ICommand LoadSessionCommand { get; }
        public ICommand BlockByNameCommand { get; }
        public ICommand MoveRuleUpCommand { get; }
        public ICommand MoveRuleDownCommand { get; }

        public MainViewModel()
        {
            _driverService = new DriverService();
            _processService = new ProcessService();

            _statusTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
            _statusTimer.Tick += (s, e) => UpdateStatus();

            ConnectToDriverCommand = new RelayCommand(ConnectToDriverExecute);
            ToggleFirewallCommand = new RelayCommand(ToggleFirewallExecute);
            RefreshProcessesCommand = new RelayCommand(RefreshProcessesExecute);
            BlockSelectedProcessCommand = new RelayCommand(BlockSelectedProcessExecute);
            BlockSelectedProcessesCommand = new RelayCommand(BlockSelectedProcessesExecute);
            UnblockSelectedAppCommand = new RelayCommand(UnblockSelectedAppExecute);
            UnblockAllAppsCommand = new RelayCommand(UnblockAllAppsExecute);
            AddRuleCommand = new RelayCommand(AddRuleExecute);
            RemoveSelectedRuleCommand = new RelayCommand(RemoveSelectedRuleExecute);
            ClearAllRulesCommand = new RelayCommand(ClearAllRulesExecute);
            UseSelectedProcessPathCommand = new RelayCommand(UseSelectedProcessPathExecute);
            SelectAllProcessesCommand = new RelayCommand(SelectAllProcessesExecute);
            DeselectAllProcessesCommand = new RelayCommand(DeselectAllProcessesExecute);
            SaveSessionCommand = new RelayCommand(SaveSessionExecute);
            LoadSessionCommand = new RelayCommand(LoadSessionExecute);
            BlockByNameCommand = new RelayCommand(BlockByNameExecute);
            MoveRuleUpCommand = new RelayCommand(MoveRuleUpExecute);
            MoveRuleDownCommand = new RelayCommand(MoveRuleDownExecute);
        }

        public void Initialize()
        {
            ProcessRegistryService.Instance.Clear();
            ConnectToDriverExecute();
            LoadFromRegistry();
            RefreshProcessesExecute();
            _statusTimer.Start();
        }

        private void LoadFromRegistry()
        {
            if (!IsConnected) return;
            var session = SessionService.LoadFromRegistry();
            if (session == null) return;

            foreach (var appData in session.BlockedApps)
            {
                var app = SessionService.ToBlockedApp(appData);
                if (_driverService.BlockApp(app.ApplicationPath, app.ProcessId))
                    BlockedApps.Add(app);
            }

            foreach (var ruleData in session.Rules)
            {
                var rule = SessionService.ToFirewallRule(ruleData);
                if (_driverService.AddRule(rule))
                    Rules.Add(rule);
            }

            LogService.Log($"Registry: Restored {BlockedApps.Count} blocked, {Rules.Count} rules");
        }

        private void SyncProcessStats()
        {
            if (!IsConnected) return;
            try
            {
                var stats = _driverService.GetProcessStats();
                if (stats == null) return;

                foreach (var process in RunningProcesses)
                {
                    // Match by process name (case-insensitive)
                    uint sent = 0, recv = 0, blocked = 0;
                    foreach (var s in stats)
                    {
                        if (s.ProcessName.Equals(process.ProcessName, StringComparison.OrdinalIgnoreCase))
                        {
                            sent += s.PacketsSent;
                            recv += s.PacketsRecv;
                            blocked += s.PacketsBlocked;
                        }
                    }
                    process.PacketsSent = sent;
                    process.PacketsRecv = recv;
                    process.PacketsBlockedCount = blocked;
                }
            }
            catch { }
        }

        private void ConnectToDriverExecute()
        {
            IsConnected = _driverService.Connect();
            StatusText = IsConnected ? "[CONNECTED]" : "[DRIVER NOT FOUND]";
            UpdateStatus();
        }

        private void UpdateStatus()
        {
            if (!IsConnected) return;
            var status = _driverService.GetStatus();
            if (status != null)
            {
                IsFirewallEnabled = status.IsEnabled;
                PacketsBlocked = status.PacketsBlocked;
                PacketsAllowed = status.PacketsAllowed;
                StatusText = IsFirewallEnabled ? "[FIREWALL ACTIVE]" : "[FIREWALL DISABLED]";
            }
            SyncProcessStats();
            PollDriverLog();
        }

        private void PollDriverLog()
        {
            if (!IsConnected) return;
            try
            {
                var log = _driverService.GetDebugLog();
                if (!string.IsNullOrEmpty(log))
                    LogService.Log("[DRIVER] " + log.TrimEnd());
            }
            catch { }
        }

        private void ToggleFirewallExecute()
        {
            if (!IsConnected) return;
            if (IsFirewallEnabled) _driverService.DisableFirewall();
            else _driverService.EnableFirewall();
            UpdateStatus();
        }

        private void RefreshProcessesExecute()
        {
            RunningProcesses.Clear();
            var processRegistry = ProcessRegistryService.Instance;

            foreach (var process in _processService.GetRunningProcesses())
            {
                if (!string.IsNullOrWhiteSpace(process.ExecutablePath) && !process.ExecutablePath.StartsWith("PID:"))
                    processRegistry.RegisterProcess(process.ProcessName, process.ExecutablePath);

                process.IsBlocked = BlockedApps.Any(b =>
                    b.ApplicationPath.Equals(process.ExecutablePath, StringComparison.OrdinalIgnoreCase));
                RunningProcesses.Add(process);
            }

            LogService.Log($"ProcessRegistry: {processRegistry.GetStatistics()}");
        }

        private void BlockSelectedProcessExecute()
        {
            if (SelectedProcess == null || !IsConnected) return;
            if (_driverService.BlockApp(SelectedProcess.ExecutablePath, SelectedProcess.ProcessId))
            {
                BlockedApps.Add(new BlockedApp
                {
                    ApplicationPath = SelectedProcess.ExecutablePath,
                    ApplicationName = SelectedProcess.ProcessName,
                    ProcessId = SelectedProcess.ProcessId,
                    IsBlocked = true
                });
                SelectedProcess.IsBlocked = true;
            }
        }

        private void BlockSelectedProcessesExecute()
        {
            if (!IsConnected) return;
            foreach (var process in RunningProcesses.Where(p => p.IsSelected && !p.IsBlocked).ToList())
            {
                if (_driverService.BlockApp(process.ExecutablePath, process.ProcessId))
                {
                    BlockedApps.Add(new BlockedApp
                    {
                        ApplicationPath = process.ExecutablePath,
                        ApplicationName = process.ProcessName,
                        ProcessId = process.ProcessId,
                        IsBlocked = true
                    });
                    process.IsBlocked = true;
                    process.IsSelected = false;
                }
            }
        }

        private void BlockByNameExecute()
        {
            if (SelectedProcess == null || !IsConnected) return;

            var name = SelectedProcess.ProcessName;
            var matches = RunningProcesses
                .Where(p => p.ProcessName.Equals(name, StringComparison.OrdinalIgnoreCase) && !p.IsBlocked)
                .ToList();

            if (matches.Count == 0) return;

            int blocked = 0;
            foreach (var process in matches)
            {
                if (_driverService.BlockApp(process.ExecutablePath, process.ProcessId))
                {
                    BlockedApps.Add(new BlockedApp
                    {
                        ApplicationPath = process.ExecutablePath,
                        ApplicationName = process.ProcessName,
                        ProcessId = process.ProcessId,
                        IsBlocked = true
                    });
                    process.IsBlocked = true;
                    blocked++;
                }
            }

            LogService.Log($"BlockByName: {name} - blocked {blocked}/{matches.Count} instances");
        }

        private void UnblockSelectedAppExecute()
        {
            if (SelectedBlockedApp == null || !IsConnected) return;
            if (_driverService.UnblockApp(SelectedBlockedApp.ApplicationPath))
            {
                var process = RunningProcesses.FirstOrDefault(p =>
                    p.ExecutablePath.Equals(SelectedBlockedApp.ApplicationPath, StringComparison.OrdinalIgnoreCase));
                if (process != null) process.IsBlocked = false;
                BlockedApps.Remove(SelectedBlockedApp);
            }
        }

        private void UnblockAllAppsExecute()
        {
            if (!IsConnected) return;
            foreach (var app in BlockedApps.ToList())
                _driverService.UnblockApp(app.ApplicationPath);
            BlockedApps.Clear();
            foreach (var process in RunningProcesses)
                process.IsBlocked = false;
        }

        private void AddRuleExecute()
        {
            if (!IsConnected) return;

            uint processId = 0;
            string appPath = "";
            string appName = "* (all)";

            if (!string.IsNullOrWhiteSpace(NewRulePath) && NewRulePath.Trim() != "*")
            {
                appPath = NewRulePath;
                if (NewRulePath.StartsWith("PID:", StringComparison.OrdinalIgnoreCase))
                {
                    var pidStr = NewRulePath.Substring(4);
                    if (uint.TryParse(pidStr, out var pid))
                    {
                        processId = pid;
                        appPath = $"PID:{pid}";
                        appName = $"PID:{processId}";
                    }
                }
                else
                {
                    appName = _processService.GetProcessNameFromPath(appPath);
                }
            }

            var rule = new FirewallRule
            {
                ApplicationPath = appPath,
                ApplicationName = appName,
                ProcessId = processId,
                Action = NewRuleAction,
                Direction = NewRuleDirection,
                IsActive = true
            };

            if (!string.IsNullOrWhiteSpace(NewRulePorts))
            {
                foreach (var portSpec in NewRulePorts.Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries))
                {
                    var trimmed = portSpec.Trim();
                    if (trimmed.Contains("-"))
                    {
                        var parts = trimmed.Split('-');
                        if (parts.Length == 2 &&
                            ushort.TryParse(parts[0].Trim(), out var start) &&
                            ushort.TryParse(parts[1].Trim(), out var end))
                        {
                            rule.PortRanges.Add(new PortRange { StartPort = start, EndPort = end });
                        }
                    }
                    else if (ushort.TryParse(trimmed, out var port))
                    {
                        rule.PortRanges.Add(new PortRange { StartPort = port, EndPort = port });
                    }
                }
            }

            if (!string.IsNullOrWhiteSpace(NewRuleIps))
            {
                foreach (var ipSpec in NewRuleIps.Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries))
                {
                    var trimmed = ipSpec.Trim();
                    try
                    {
                        if (!ValidateIpAddress(trimmed, out string error))
                        {
                            MessageBox.Show($"Invalid IP format: {trimmed}\n{error}", "Error",
                                MessageBoxButton.OK, MessageBoxImage.Warning);
                            return;
                        }
                        rule.IpAddresses.Add(IpAddressEntry.FromString(trimmed));
                    }
                    catch (Exception ex)
                    {
                        MessageBox.Show($"IP parse error: {trimmed}\n{ex.Message}", "Error",
                            MessageBoxButton.OK, MessageBoxImage.Error);
                        return;
                    }
                }
            }

            if (_driverService.AddRule(rule))
            {
                Rules.Add(rule);
                NewRulePath = "";
                NewRulePorts = "";
                NewRuleIps = "";
            }
        }

        private void RemoveSelectedRuleExecute()
        {
            if (SelectedRule == null || !IsConnected) return;
            if (_driverService.RemoveRule(SelectedRule.RuleId))
                Rules.Remove(SelectedRule);
        }

        private void ClearAllRulesExecute()
        {
            if (!IsConnected) return;
            if (_driverService.ClearRules())
                Rules.Clear();
        }

        private void MoveRuleUpExecute()
        {
            if (SelectedRule == null) return;
            int idx = Rules.IndexOf(SelectedRule);
            if (idx <= 0) return;
            Rules.Move(idx, idx - 1);
            ReapplyRulesToDriver();
        }

        private void MoveRuleDownExecute()
        {
            if (SelectedRule == null) return;
            int idx = Rules.IndexOf(SelectedRule);
            if (idx < 0 || idx >= Rules.Count - 1) return;
            Rules.Move(idx, idx + 1);
            ReapplyRulesToDriver();
        }

        private void ReapplyRulesToDriver()
        {
            if (!IsConnected) return;
            _driverService.ClearRules();
            foreach (var rule in Rules)
            {
                rule.RuleId = 0;
                _driverService.AddRule(rule);
            }
            LogService.Log($"Rules reapplied: {Rules.Count} rules in new order");
        }

        private void UseSelectedProcessPathExecute()
        {
            if (SelectedProcess != null)
                NewRulePath = SelectedProcess.ExecutablePath;
        }

        private void SelectAllProcessesExecute()
        {
            foreach (var process in RunningProcesses.Where(p => p.CanBeBlocked))
                process.IsSelected = true;
        }

        private void DeselectAllProcessesExecute()
        {
            foreach (var process in RunningProcesses)
                process.IsSelected = false;
        }

        private void SaveSessionExecute()
        {
            if (!IsConnected) return;
            var saveDialog = new Microsoft.Win32.SaveFileDialog
            {
                Title = "Save Session",
                Filter = "Firewall Session (*.fwsession)|*.fwsession|All Files (*.*)|*.*",
                DefaultExt = ".fwsession",
                FileName = $"FirewallSession_{DateTime.Now:yyyy-MM-dd_HH-mm-ss}.fwsession"
            };

            if (saveDialog.ShowDialog() == true)
            {
                if (SessionService.SaveSession(saveDialog.FileName, BlockedApps, Rules))
                {
                    MessageBox.Show($"Session saved!\n\nFile: {saveDialog.FileName}\nBlocked: {BlockedApps.Count}\nRules: {Rules.Count}",
                        "Session", MessageBoxButton.OK, MessageBoxImage.Information);
                    LogService.Log($"Session saved to: {saveDialog.FileName}");
                }
            }
        }

        private void LoadSessionExecute()
        {
            if (!IsConnected) return;
            var openDialog = new Microsoft.Win32.OpenFileDialog
            {
                Title = "Load Session",
                Filter = "Firewall Session (*.fwsession)|*.fwsession|All Files (*.*)|*.*",
                DefaultExt = ".fwsession"
            };

            if (openDialog.ShowDialog() == true)
            {
                var sessionData = SessionService.LoadSession(openDialog.FileName);
                if (sessionData != null)
                {
                    var result = MessageBox.Show(
                        $"Load session?\n\nCreated: {sessionData.Timestamp:yyyy-MM-dd HH:mm:ss}\nBlocked: {sessionData.BlockedApps.Count}\nRules: {sessionData.Rules.Count}\n\nCurrent data will be replaced!",
                        "Load Session", MessageBoxButton.YesNo, MessageBoxImage.Question);

                    if (result == MessageBoxResult.Yes)
                    {
                        UnblockAllAppsExecute();
                        ClearAllRulesExecute();

                        foreach (var appData in sessionData.BlockedApps)
                        {
                            var app = SessionService.ToBlockedApp(appData);
                            if (_driverService.BlockApp(app.ApplicationPath, app.ProcessId))
                                BlockedApps.Add(app);
                        }

                        foreach (var ruleData in sessionData.Rules)
                        {
                            var rule = SessionService.ToFirewallRule(ruleData);
                            if (_driverService.AddRule(rule))
                                Rules.Add(rule);
                        }

                        LogService.Log($"Session loaded from: {openDialog.FileName}");
                        RefreshProcessesExecute();
                    }
                }
            }
        }

        public void Cleanup()
        {
            _statusTimer.Stop();
            try { SessionService.SaveToRegistry(BlockedApps, Rules); } catch { }
            try { _driverService.Dispose(); } catch { }
        }

        private bool ValidateIpAddress(string input, out string error)
        {
            error = "";
            if (string.IsNullOrWhiteSpace(input)) { error = "IP address cannot be empty"; return false; }

            var parts = input.Split('/');
            string address = parts[0];
            string prefix = parts.Length > 1 ? parts[1] : null;

            if (address.Contains(":"))
            {
                if (!System.Net.IPAddress.TryParse(address, out var ipv6))
                { error = "Invalid IPv6 format"; return false; }
                if (ipv6.AddressFamily != System.Net.Sockets.AddressFamily.InterNetworkV6)
                { error = "Must be IPv6"; return false; }
                if (prefix != null && (!byte.TryParse(prefix, out byte pfx) || pfx > 128))
                { error = "IPv6 prefix must be 0-128"; return false; }
            }
            else
            {
                if (!System.Net.IPAddress.TryParse(address, out var ipv4))
                { error = "Invalid IPv4 format"; return false; }
                if (ipv4.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
                { error = "Must be IPv4"; return false; }
                if (prefix != null)
                {
                    if (prefix.Contains("."))
                    {
                        if (!System.Net.IPAddress.TryParse(prefix, out _))
                        { error = "Invalid subnet mask"; return false; }
                    }
                    else if (!int.TryParse(prefix, out int cidr) || cidr < 0 || cidr > 32)
                    { error = "CIDR must be 0-32"; return false; }
                }
            }
            return true;
        }
    }
}
