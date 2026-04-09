using System;
using System.ComponentModel;
using System.Windows;
using System.Windows.Controls;
using HackerFirewall.Models;
using HackerFirewall.ViewModels;

namespace HackerFirewall.Views
{
    public partial class MainWindow : HackerWindow
    {
        private readonly MainViewModel _viewModel;

        public MainWindow()
        {
            _viewModel = new MainViewModel();
            DataContext = _viewModel;
            InitializeComponent();
            Loaded += (s, e) => _viewModel.Initialize();
            Closing += OnWindowClosing;
        }

        private void OnWindowClosing(object sender, CancelEventArgs e)
        {
            try { _viewModel.Cleanup(); } catch { }
            Application.Current.Shutdown();
            Environment.Exit(0);
        }

        private void Exit_Click(object sender, RoutedEventArgs e) => Close();

        private void OpenTrafficMonitor_Click(object sender, RoutedEventArgs e)
        {
            var window = new TrafficMonitorWindow(_viewModel.DriverService);
            window.Show();
        }

        private void OpenLog_Click(object sender, RoutedEventArgs e)
        {
            var window = new LogWindow();
            window.Show();
        }

        private void ActionBlock_Checked(object sender, RoutedEventArgs e)
        {
            if (_viewModel != null) _viewModel.NewRuleAction = FirewallAction.Block;
        }

        private void ActionAllow_Checked(object sender, RoutedEventArgs e)
        {
            if (_viewModel != null) _viewModel.NewRuleAction = FirewallAction.Allow;
        }

        private void ActionRestrict_Checked(object sender, RoutedEventArgs e)
        {
            if (_viewModel != null) _viewModel.NewRuleAction = FirewallAction.AllowRestricted;
        }

        private void Direction_Changed(object sender, SelectionChangedEventArgs e)
        {
            if (_viewModel != null && sender is ComboBox cb && cb.SelectedIndex >= 0)
                _viewModel.NewRuleDirection = (TrafficDirection)cb.SelectedIndex;
        }
    }
}
