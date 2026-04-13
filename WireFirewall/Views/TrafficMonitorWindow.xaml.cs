using System.Collections.Specialized;
using System.Windows;
using HackerFirewall.Models;
using HackerFirewall.Services;
using HackerFirewall.ViewModels;

namespace HackerFirewall.Views
{
    public partial class TrafficMonitorWindow : HackerWindow
    {
        private readonly TrafficMonitorViewModel _viewModel;

        public TrafficMonitorWindow(DriverService driverService, string processFilter = "")
        {
            InitializeComponent();
            _viewModel = new TrafficMonitorViewModel(driverService, processFilter);
            DataContext = _viewModel;
            Loaded += OnLoaded;
            Closing += (s, e) => _viewModel.Cleanup();
        }

        private void OnLoaded(object sender, RoutedEventArgs e)
        {
            _viewModel.Start();
            _viewModel.TrafficEntries.CollectionChanged += OnTrafficChanged;
        }

        private void OnTrafficChanged(object sender, NotifyCollectionChangedEventArgs e)
        {
            if (e.Action == NotifyCollectionChangedAction.Add && _viewModel.AutoScroll)
            {
                if (TrafficList.Items.Count > 0)
                    TrafficList.ScrollIntoView(TrafficList.Items[TrafficList.Items.Count - 1]);
            }
        }

        private void InspectPacket_Click(object sender, RoutedEventArgs e)
        {
            if (_viewModel.FrozenEntry != null)
            {
                var viewer = new PacketViewerWindow(_viewModel.FrozenEntry);
                viewer.Show();
            }
        }
    }
}
