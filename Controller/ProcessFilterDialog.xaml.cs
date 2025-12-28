using System.Windows;

namespace FirewallController
{
    public partial class ProcessFilterDialog : Window
    {
        public string ProcessFilter { get; private set; } = "";

        public ProcessFilterDialog()
        {
            InitializeComponent();
            ProcessNameBox.Focus();
        }

        private void Ok_Click(object sender, RoutedEventArgs e)
        {
            ProcessFilter = ProcessNameBox.Text.Trim();
            DialogResult = true;
            Close();
        }

        private void Cancel_Click(object sender, RoutedEventArgs e)
        {
            DialogResult = false;
            Close();
        }
    }
}

