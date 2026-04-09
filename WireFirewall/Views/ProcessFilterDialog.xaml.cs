using System.Windows;

namespace HackerFirewall.Views
{
    public partial class ProcessFilterDialog : HackerWindow
    {
        public string FilterResult { get; private set; } = "";

        public ProcessFilterDialog()
        {
            InitializeComponent();
            FilterTextBox.Focus();
        }

        private void Ok_Click(object sender, RoutedEventArgs e)
        {
            FilterResult = FilterTextBox.Text.Trim();
            DialogResult = true;
        }

        private void Cancel_Click(object sender, RoutedEventArgs e)
        {
            DialogResult = false;
        }
    }
}
