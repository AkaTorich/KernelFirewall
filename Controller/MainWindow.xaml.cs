using System.Windows;
using FirewallController.Models;
using FirewallController.Services;
using FirewallController.ViewModels;

namespace FirewallController
{
    public partial class MainWindow : Window
    {
        private MainViewModel? _viewModel;
        private TrafficMonitorWindow? _monitorWindow;

        public MainWindow()
        {
            InitializeComponent();
            Loaded += MainWindow_Loaded;
            Closing += MainWindow_Closing;
        }

        private void MainWindow_Loaded(object sender, RoutedEventArgs e)
        {
            _viewModel = DataContext as MainViewModel;
            _viewModel?.Initialize();
        }

        private void MainWindow_Closing(object? sender, System.ComponentModel.CancelEventArgs e)
        {
            _monitorWindow?.Close();
            _viewModel?.Cleanup();
        }

        private void OpenMonitor_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new ProcessFilterDialog();
            dialog.Owner = this;
            
            if (dialog.ShowDialog() == true)
            {
                if (_monitorWindow == null || !_monitorWindow.IsLoaded)
                {
                    _monitorWindow = new TrafficMonitorWindow(_viewModel!.DriverService, dialog.ProcessFilter);
                    _monitorWindow.Show();
                }
                else
                {
                    _monitorWindow.Activate();
                }
            }
        }

        private void OpenLog_Click(object sender, RoutedEventArgs e)
        {
            var logWindow = LogWindow.Instance;
            logWindow.Show();
            logWindow.Activate();
        }

        private void BlockAction_Checked(object sender, RoutedEventArgs e)
        {
            if (_viewModel != null)
                _viewModel.NewRuleAction = FirewallAction.Block;
        }

        private void AllowAction_Checked(object sender, RoutedEventArgs e)
        {
            if (_viewModel != null)
                _viewModel.NewRuleAction = FirewallAction.Allow;
        }

        private void RestrictAction_Checked(object sender, RoutedEventArgs e)
        {
            if (_viewModel != null)
                _viewModel.NewRuleAction = FirewallAction.AllowRestricted;
        }

        private void Exit_Click(object sender, RoutedEventArgs e)
        {
            Close();
        }
    }
}

