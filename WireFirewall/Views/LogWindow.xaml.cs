using System;
using System.Windows;
using HackerFirewall.Infrastructure;

namespace HackerFirewall.Views
{
    public partial class LogWindow : HackerWindow
    {
        public LogWindow()
        {
            InitializeComponent();
            LogService.OnLog += OnLogMessage;
            Closing += (s, e) => LogService.OnLog -= OnLogMessage;
        }

        private void OnLogMessage(string message)
        {
            try
            {
                Dispatcher.BeginInvoke(new Action(() =>
                {
                    try
                    {
                        LogText.AppendText(message + "\n");
                        LogText.ScrollToEnd();
                    }
                    catch { }
                }));
            }
            catch { }
        }

        private void Clear_Click(object sender, RoutedEventArgs e)
        {
            LogText.Clear();
        }
    }
}
