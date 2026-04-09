using System.Windows;
using System.Windows.Input;

namespace HackerFirewall.Views
{
    public class HackerWindow : Window
    {
        public HackerWindow()
        {
            WindowStyle = WindowStyle.None;
            AllowsTransparency = true;
            Background = System.Windows.Media.Brushes.Transparent;
            ResizeMode = ResizeMode.CanResizeWithGrip;
        }

        protected void TitleBar_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
        {
            if (e.ClickCount == 2)
                ToggleMaximize();
            else
                DragMove();
        }

        protected void Minimize_Click(object sender, RoutedEventArgs e)
            => WindowState = WindowState.Minimized;

        protected void Maximize_Click(object sender, RoutedEventArgs e)
            => ToggleMaximize();

        protected void CloseWindow_Click(object sender, RoutedEventArgs e)
            => Close();

        private void ToggleMaximize()
        {
            WindowState = WindowState == WindowState.Maximized
                ? WindowState.Normal
                : WindowState.Maximized;
        }
    }
}
