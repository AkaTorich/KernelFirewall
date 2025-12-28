using System;
using System.Windows;

namespace FirewallController
{
    public partial class LogWindow : Window
    {
        private static LogWindow? _instance;
        
        public static LogWindow Instance
        {
            get
            {
                if (_instance == null || !_instance.IsLoaded)
                {
                    _instance = new LogWindow();
                }
                return _instance;
            }
        }

        public LogWindow()
        {
            InitializeComponent();
        }

        public static void Log(string message)
        {
            try
            {
                var timestamp = DateTime.Now.ToString("HH:mm:ss.fff");
                var line = $"[{timestamp}] {message}\n";
                
                System.Diagnostics.Debug.WriteLine(line);
                
                if (_instance != null && _instance.IsLoaded)
                {
                    _instance.Dispatcher.BeginInvoke(() =>
                    {
                        try
                        {
                            _instance.LogText.AppendText(line);
                            _instance.LogText.ScrollToEnd();
                        }
                        catch { }
                    });
                }
            }
            catch { }
        }

        private void Clear_Click(object sender, RoutedEventArgs e)
        {
            LogText.Clear();
        }
    }
}

