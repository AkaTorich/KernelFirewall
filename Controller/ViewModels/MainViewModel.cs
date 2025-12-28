using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using FirewallController.Models;
using FirewallController.Services;

namespace FirewallController.ViewModels
{
    public partial class MainViewModel : ObservableObject
    {
        private readonly DriverService _driverService;
        private readonly ProcessService _processService;
        private readonly DispatcherTimer _statusTimer;

        public DriverService DriverService => _driverService;

        [ObservableProperty] private bool _isConnected;
        [ObservableProperty] private bool _isFirewallEnabled;
        [ObservableProperty] private uint _packetsBlocked;
        [ObservableProperty] private uint _packetsAllowed;
        [ObservableProperty] private string _statusText = "Отключено";

        [ObservableProperty] private ObservableCollection<ProcessInfo> _runningProcesses = new();
        [ObservableProperty] private ObservableCollection<BlockedApp> _blockedApps = new();
        [ObservableProperty] private ObservableCollection<FirewallRule> _rules = new();

        [ObservableProperty] private ProcessInfo? _selectedProcess;
        [ObservableProperty] private BlockedApp? _selectedBlockedApp;
        [ObservableProperty] private FirewallRule? _selectedRule;

        // New rule fields
        [ObservableProperty] private string _newRulePath = "";
        [ObservableProperty] private FirewallAction _newRuleAction = FirewallAction.Block;
        [ObservableProperty] private TrafficDirection _newRuleDirection = TrafficDirection.Output;
        [ObservableProperty] private string _newRulePorts = "";
        [ObservableProperty] private string _newRuleIps = "";

        // Process filter options
        [ObservableProperty] private bool _showSystemProcesses = false;
        [ObservableProperty] private bool _showAllInstances = true;

        partial void OnShowSystemProcessesChanged(bool value)
        {
            _processService.ShowSystemProcesses = value;
            RefreshProcesses();
        }

        partial void OnShowAllInstancesChanged(bool value)
        {
            _processService.ShowDuplicatePaths = value;
            RefreshProcesses();
        }

        public MainViewModel()
        {
            _driverService = new DriverService();
            _processService = new ProcessService();

            _statusTimer = new DispatcherTimer
            {
                Interval = TimeSpan.FromSeconds(1)
            };
            _statusTimer.Tick += StatusTimer_Tick;
        }

        public void Initialize()
        {
            // Clear previous process registry on startup
            ProcessRegistryService.Instance.Clear();
            LogWindow.Log("ProcessRegistry: Cleared on startup");

            ConnectToDriver();
            RefreshProcesses();
            _statusTimer.Start();
        }

        private void StatusTimer_Tick(object? sender, EventArgs e)
        {
            UpdateStatus();
        }

        [RelayCommand]
        private void ConnectToDriver()
        {
            IsConnected = _driverService.Connect();
            StatusText = IsConnected ? "Подключено к драйверу" : "Драйвер не найден";
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
                StatusText = IsFirewallEnabled ? "🛡️ Активен" : "⚠️ Отключен";
            }
        }

        [RelayCommand]
        private void ToggleFirewall()
        {
            if (!IsConnected) return;

            if (IsFirewallEnabled)
            {
                _driverService.DisableFirewall();
            }
            else
            {
                _driverService.EnableFirewall();
            }
            UpdateStatus();
        }

        [RelayCommand]
        private void RefreshProcesses()
        {
            RunningProcesses.Clear();
            var processRegistry = ProcessRegistryService.Instance;

            foreach (var process in _processService.GetRunningProcesses())
            {
                // Register process in global registry (only adds new, never removes)
                if (!string.IsNullOrWhiteSpace(process.ExecutablePath) &&
                    !process.ExecutablePath.StartsWith("PID:"))
                {
                    processRegistry.RegisterProcess(process.ProcessName, process.ExecutablePath);
                }

                // Check if already blocked
                process.IsBlocked = BlockedApps.Any(b =>
                    b.ApplicationPath.Equals(process.ExecutablePath, StringComparison.OrdinalIgnoreCase));
                RunningProcesses.Add(process);
            }

            LogWindow.Log($"ProcessRegistry: {processRegistry.GetStatistics()}");
        }

        [RelayCommand]
        private void BlockSelectedProcess()
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

        [RelayCommand]
        private void BlockSelectedProcesses()
        {
            if (!IsConnected) return;

            foreach (var process in RunningProcesses.Where(p => p.IsSelected && !p.IsBlocked))
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

        [RelayCommand]
        private void UnblockSelectedApp()
        {
            if (SelectedBlockedApp == null || !IsConnected) return;

            if (_driverService.UnblockApp(SelectedBlockedApp.ApplicationPath))
            {
                var process = RunningProcesses.FirstOrDefault(p => 
                    p.ExecutablePath.Equals(SelectedBlockedApp.ApplicationPath, StringComparison.OrdinalIgnoreCase));
                if (process != null)
                {
                    process.IsBlocked = false;
                }
                BlockedApps.Remove(SelectedBlockedApp);
            }
        }

        [RelayCommand]
        private void UnblockAllApps()
        {
            if (!IsConnected) return;

            foreach (var app in BlockedApps.ToList())
            {
                _driverService.UnblockApp(app.ApplicationPath);
            }
            BlockedApps.Clear();

            foreach (var process in RunningProcesses)
            {
                process.IsBlocked = false;
            }
        }

        [RelayCommand]
        private void AddRule()
        {
            if (!IsConnected) return;

            uint processId = 0;
            string appPath = "";
            string appName = "Все процессы";

            // Check if process is specified
            if (!string.IsNullOrWhiteSpace(NewRulePath))
            {
                appPath = NewRulePath;

                // Check if this is a PID-based rule (format: "PID:4")
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

            // Parse ports
            if (!string.IsNullOrWhiteSpace(NewRulePorts))
            {
                foreach (var portSpec in NewRulePorts.Split(',', StringSplitOptions.RemoveEmptyEntries))
                {
                    var trimmed = portSpec.Trim();
                    if (trimmed.Contains('-'))
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

            // Parse IPs (supports both IPv4 and IPv6)
            if (!string.IsNullOrWhiteSpace(NewRuleIps))
            {
                foreach (var ipSpec in NewRuleIps.Split(',', StringSplitOptions.RemoveEmptyEntries))
                {
                    var trimmed = ipSpec.Trim();
                    try
                    {
                        // Validate IP address format
                        if (!ValidateIpAddress(trimmed, out string error))
                        {
                            MessageBox.Show($"Неверный формат IP адреса: {trimmed}\n{error}",
                                          "Ошибка", MessageBoxButton.OK, MessageBoxImage.Warning);
                            return;
                        }

                        // FromString now handles both IPv4 and IPv6 with CIDR notation
                        rule.IpAddresses.Add(IpAddressEntry.FromString(trimmed));
                    }
                    catch (Exception ex)
                    {
                        MessageBox.Show($"Ошибка парсинга IP адреса: {trimmed}\n{ex.Message}",
                                      "Ошибка", MessageBoxButton.OK, MessageBoxImage.Error);
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

        [RelayCommand]
        private void RemoveSelectedRule()
        {
            if (SelectedRule == null || !IsConnected) return;

            if (_driverService.RemoveRule(SelectedRule.RuleId))
            {
                Rules.Remove(SelectedRule);
            }
        }

        [RelayCommand]
        private void ClearAllRules()
        {
            if (!IsConnected) return;

            if (_driverService.ClearRules())
            {
                Rules.Clear();
            }
        }

        [RelayCommand]
        private void UseSelectedProcessPath()
        {
            if (SelectedProcess != null)
            {
                NewRulePath = SelectedProcess.ExecutablePath;
            }
        }

        [RelayCommand]
        private void SelectAllProcesses()
        {
            // Only select processes that can actually be blocked
            foreach (var process in RunningProcesses.Where(p => p.CanBeBlocked))
            {
                process.IsSelected = true;
            }
        }

        [RelayCommand]
        private void DeselectAllProcesses()
        {
            foreach (var process in RunningProcesses)
            {
                process.IsSelected = false;
            }
        }

        [RelayCommand]
        private void SaveSession()
        {
            if (!IsConnected) return;

            var saveDialog = new Microsoft.Win32.SaveFileDialog
            {
                Title = "Сохранить сессию",
                Filter = "Firewall Session (*.fwsession)|*.fwsession|All Files (*.*)|*.*",
                DefaultExt = ".fwsession",
                FileName = $"FirewallSession_{DateTime.Now:yyyy-MM-dd_HH-mm-ss}.fwsession"
            };

            if (saveDialog.ShowDialog() == true)
            {
                if (SessionService.SaveSession(saveDialog.FileName, BlockedApps, Rules))
                {
                    MessageBox.Show($"Сессия успешно сохранена!\n\nФайл: {saveDialog.FileName}\n" +
                                  $"Заблокировано приложений: {BlockedApps.Count}\n" +
                                  $"Правил фильтрации: {Rules.Count}",
                                  "Сохранение сессии", MessageBoxButton.OK, MessageBoxImage.Information);
                    LogWindow.Log($"Session saved to: {saveDialog.FileName}");
                }
                else
                {
                    MessageBox.Show("Ошибка при сохранении сессии. Проверьте лог для деталей.",
                                  "Ошибка", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        [RelayCommand]
        private void LoadSession()
        {
            if (!IsConnected) return;

            var openDialog = new Microsoft.Win32.OpenFileDialog
            {
                Title = "Загрузить сессию",
                Filter = "Firewall Session (*.fwsession)|*.fwsession|All Files (*.*)|*.*",
                DefaultExt = ".fwsession"
            };

            if (openDialog.ShowDialog() == true)
            {
                var sessionData = SessionService.LoadSession(openDialog.FileName);
                if (sessionData != null)
                {
                    // Ask for confirmation
                    var result = MessageBox.Show(
                        $"Загрузить сессию?\n\n" +
                        $"Дата создания: {sessionData.Timestamp:yyyy-MM-dd HH:mm:ss}\n" +
                        $"Заблокировано приложений: {sessionData.BlockedApps.Count}\n" +
                        $"Правил фильтрации: {sessionData.Rules.Count}\n\n" +
                        $"Текущие данные будут заменены!",
                        "Загрузка сессии",
                        MessageBoxButton.YesNo,
                        MessageBoxImage.Question);

                    if (result == MessageBoxResult.Yes)
                    {
                        // Clear current data
                        UnblockAllApps();
                        ClearAllRules();

                        int blockedCount = 0;
                        int rulesCount = 0;

                        // Load blocked apps (will block by application path, not by PID)
                        LogWindow.Log("SessionService: Loading blocked apps - blocking by application path");
                        foreach (var appData in sessionData.BlockedApps)
                        {
                            var app = SessionService.ToBlockedApp(appData);
                            if (_driverService.BlockApp(app.ApplicationPath, app.ProcessId))
                            {
                                BlockedApps.Add(app);
                                blockedCount++;
                                LogWindow.Log($"  ✓ Blocked: {app.ApplicationName} ({app.ApplicationPath})");
                            }
                        }

                        // Load rules (PID is preserved as saved)
                        LogWindow.Log("SessionService: Loading filtering rules - PID preserved");
                        foreach (var ruleData in sessionData.Rules)
                        {
                            var rule = SessionService.ToFirewallRule(ruleData);
                            if (_driverService.AddRule(rule))
                            {
                                Rules.Add(rule);
                                rulesCount++;
                                var pidInfo = rule.ProcessId > 0 ? $"PID:{rule.ProcessId}" : "by path";
                                LogWindow.Log($"  ✓ Rule: {rule.ApplicationName} ({pidInfo}) - {rule.Action}");
                            }
                        }

                        MessageBox.Show($"Сессия загружена!\n\n" +
                                      $"Заблокировано приложений: {blockedCount}/{sessionData.BlockedApps.Count}\n" +
                                      $"Правил фильтрации: {rulesCount}/{sessionData.Rules.Count}",
                                      "Загрузка сессии", MessageBoxButton.OK, MessageBoxImage.Information);
                        LogWindow.Log($"Session loaded from: {openDialog.FileName}");

                        // Refresh process list to update blocked status
                        RefreshProcesses();
                    }
                }
                else
                {
                    MessageBox.Show("Ошибка при загрузке сессии. Проверьте лог для деталей.",
                                  "Ошибка", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        public void Cleanup()
        {
            _statusTimer.Stop();
            _driverService.Dispose();
        }

        /// <summary>
        /// Validates IP address format for both IPv4 and IPv6
        /// </summary>
        /// <param name="input">IP address string (e.g., "192.168.1.0/24" or "2001:db8::/32")</param>
        /// <param name="error">Error message if validation fails</param>
        /// <returns>True if valid, false otherwise</returns>
        private bool ValidateIpAddress(string input, out string error)
        {
            error = "";

            if (string.IsNullOrWhiteSpace(input))
            {
                error = "IP адрес не может быть пустым";
                return false;
            }

            // Split address and prefix
            var parts = input.Split('/');
            string address = parts[0];
            string? prefix = parts.Length > 1 ? parts[1] : null;

            // Check if this is IPv6 (contains ':')
            if (address.Contains(':'))
            {
                // Validate IPv6
                if (!System.Net.IPAddress.TryParse(address, out var ipv6))
                {
                    error = "Неверный формат IPv6 адреса\nПример: 2001:db8::1 или fe80::/10";
                    return false;
                }

                if (ipv6.AddressFamily != System.Net.Sockets.AddressFamily.InterNetworkV6)
                {
                    error = "Адрес должен быть IPv6";
                    return false;
                }

                // Validate prefix length (0-128)
                if (prefix != null)
                {
                    if (!byte.TryParse(prefix, out byte prefixLen) || prefixLen > 128)
                    {
                        error = "Префикс IPv6 должен быть от 0 до 128\nПример: 2001:db8::/32";
                        return false;
                    }
                }
            }
            else
            {
                // Validate IPv4
                if (!System.Net.IPAddress.TryParse(address, out var ipv4))
                {
                    error = "Неверный формат IPv4 адреса\nПример: 192.168.1.0 или 10.0.0.0/8";
                    return false;
                }

                if (ipv4.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
                {
                    error = "Адрес должен быть IPv4";
                    return false;
                }

                // Validate CIDR prefix (0-32) or subnet mask
                if (prefix != null)
                {
                    // Check if it's CIDR notation or subnet mask
                    if (prefix.Contains('.'))
                    {
                        // Subnet mask format (e.g., "255.255.255.0")
                        if (!System.Net.IPAddress.TryParse(prefix, out var mask))
                        {
                            error = "Неверный формат маски подсети\nПример: 192.168.1.0/255.255.255.0";
                            return false;
                        }
                    }
                    else
                    {
                        // CIDR prefix length (e.g., "/24")
                        if (!int.TryParse(prefix, out int cidr) || cidr < 0 || cidr > 32)
                        {
                            error = "CIDR префикс должен быть от 0 до 32\nПример: 192.168.1.0/24";
                            return false;
                        }
                    }
                }
            }

            return true;
        }
    }
}

