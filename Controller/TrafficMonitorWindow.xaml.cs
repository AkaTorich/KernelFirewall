using System.Collections.Specialized;
using System.Windows;
using System.Windows.Controls;
using FirewallController.Services;
using FirewallController.ViewModels;

namespace FirewallController
{
    public partial class TrafficMonitorWindow : Window
    {
        private readonly TrafficMonitorViewModel _viewModel;

        public TrafficMonitorWindow(DriverService driverService, string processFilter = "")
        {
            InitializeComponent();
            _viewModel = new TrafficMonitorViewModel(driverService, processFilter);
            DataContext = _viewModel;
            
            if (!string.IsNullOrEmpty(processFilter))
            {
                Title = $"Traffic Monitor - {processFilter}";
            }
            
            // Auto-scroll to bottom when new items added
            _viewModel.TrafficEntries.CollectionChanged += TrafficEntries_CollectionChanged;
            
            Loaded += (s, e) => _viewModel.Start();
            Closing += (s, e) => _viewModel.Cleanup();
        }

        private void TrafficEntries_CollectionChanged(object? sender, NotifyCollectionChangedEventArgs e)
        {
            if (e.Action == NotifyCollectionChangedAction.Add && _viewModel.AutoScroll)
            {
                Dispatcher.BeginInvoke(() =>
                {
                    if (TrafficListBox.Items.Count > 0)
                    {
                        TrafficListBox.ScrollIntoView(TrafficListBox.Items[^1]);
                    }
                });
            }
        }
    }
}

