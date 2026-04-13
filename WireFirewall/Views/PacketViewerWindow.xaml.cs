using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using HackerFirewall.Models;

namespace HackerFirewall.Views
{
    public partial class PacketViewerWindow : HackerWindow
    {
        private readonly TrafficEntry _entry;

        public PacketViewerWindow(TrafficEntry entry)
        {
            InitializeComponent();
            _entry = entry;
            BuildTree();
        }

        private void BuildTree()
        {
            SummaryText.Text = $"{_entry.ProcessName}  {_entry.LocalAddress} {_entry.DirectionArrow} {_entry.RemoteAddress}  {_entry.StatusText}";

            // Status
            var statusNode = MakeNode(_entry.WasBlocked ? "BLOCKED" : "ALLOWED",
                _entry.WasBlocked ? Brushes.Red : Brushes.LimeGreen);
            statusNode.Items.Add(MakeLeaf("Status", _entry.StatusText));
            statusNode.Items.Add(MakeLeaf("Timestamp", _entry.Timestamp.ToString("yyyy-MM-dd HH:mm:ss.fff")));
            statusNode.Items.Add(MakeLeaf("UTC Offset", _entry.UtcOffset));
            statusNode.IsExpanded = true;
            PacketTree.Items.Add(statusNode);

            // Layer 2 - Ethernet
            var ethNode = MakeNode("Ethernet II", new SolidColorBrush(Color.FromRgb(0, 191, 255)));
            ethNode.Items.Add(MakeLeaf("EtherType", _entry.EtherType));
            ethNode.Items.Add(MakeLeaf("Source MAC", _entry.SourceMac));
            ethNode.Items.Add(MakeLeaf("Destination MAC", _entry.DestinationMac));
            ethNode.IsExpanded = true;
            PacketTree.Items.Add(ethNode);

            // Layer 3 - IP
            var ipNode = MakeNode($"Internet Protocol {_entry.IpVersionHeader}", new SolidColorBrush(Color.FromRgb(0, 255, 136)));
            ipNode.Items.Add(MakeLeaf("Version", _entry.IpVersionHeader));
            ipNode.Items.Add(MakeLeaf("Protocol", _entry.IpProtocolInfo));
            ipNode.Items.Add(MakeLeaf("Source IP", _entry.LocalIpOnly));
            ipNode.Items.Add(MakeLeaf("Source Port", _entry.LocalPortOnly.ToString()));
            ipNode.Items.Add(MakeLeaf("Destination IP", _entry.RemoteIpOnly));
            ipNode.Items.Add(MakeLeaf("Destination Port", _entry.RemotePortOnly.ToString()));
            ipNode.IsExpanded = true;
            PacketTree.Items.Add(ipNode);

            // Layer 4 - Transport
            var color4 = _entry.Protocol == ProtocolType.TCP
                ? new SolidColorBrush(Color.FromRgb(100, 149, 237))
                : new SolidColorBrush(Color.FromRgb(255, 165, 0));
            var transNode = MakeNode($"{_entry.ProtocolText} ({_entry.IpProtocolInfo})", color4);
            transNode.Items.Add(MakeLeaf("Protocol", _entry.ProtocolText));
            transNode.Items.Add(MakeLeaf("Source Port", _entry.LocalPortOnly.ToString()));
            transNode.Items.Add(MakeLeaf("Destination Port", _entry.RemotePortOnly.ToString()));
            transNode.Items.Add(MakeLeaf("Direction", _entry.DirectionText));
            transNode.IsExpanded = true;
            PacketTree.Items.Add(transNode);

            // Layer 7 - Application
            var appNode = MakeNode("Application Data", new SolidColorBrush(Color.FromRgb(255, 85, 85)));
            appNode.Items.Add(MakeLeaf("Process", _entry.ProcessName));
            appNode.Items.Add(MakeLeaf("PID", _entry.ProcessId.ToString()));
            appNode.Items.Add(MakeLeaf("Service Guess", _entry.ServiceGuess));
            appNode.Items.Add(MakeLeaf("Payload Size", $"{_entry.PacketDataLength} bytes"));
            appNode.Items.Add(MakeLeaf("Path Language", _entry.PathLanguage));
            appNode.IsExpanded = true;
            PacketTree.Items.Add(appNode);

            // Raw Data
            if (_entry.PacketData != null && _entry.PacketData.Length > 0)
            {
                var rawNode = MakeNode($"Data ({_entry.PacketData.Length} bytes)", new SolidColorBrush(Color.FromRgb(136, 136, 136)));
                // Show first bytes as child nodes
                int rows = (_entry.PacketData.Length + 15) / 16;
                for (int r = 0; r < rows && r < 64; r++)
                {
                    int off = r * 16;
                    var sb = new StringBuilder();
                    sb.Append($"{off:X4}  ");
                    var ascii = new StringBuilder();
                    for (int c = 0; c < 16; c++)
                    {
                        int idx = off + c;
                        if (idx < _entry.PacketData.Length)
                        {
                            byte b = _entry.PacketData[idx];
                            sb.Append($"{b:X2} ");
                            ascii.Append(b >= 32 && b < 127 ? (char)b : '.');
                        }
                        else
                        {
                            sb.Append("   ");
                        }
                        if (c == 7) sb.Append(" ");
                    }
                    sb.Append($" | {ascii}");
                    rawNode.Items.Add(MakeLeaf(null, sb.ToString()));
                }
                rawNode.IsExpanded = false;
                PacketTree.Items.Add(rawNode);
            }

            HexDumpText.Text = _entry.PacketHexDump;
        }

        private TreeViewItem MakeNode(string header, Brush color)
        {
            var item = new TreeViewItem
            {
                Header = new TextBlock
                {
                    Text = $"▶ {header}",
                    FontWeight = FontWeights.Bold,
                    Foreground = color,
                    FontFamily = new FontFamily("Consolas")
                },
                Foreground = new SolidColorBrush(Color.FromRgb(0, 170, 0))
            };
            return item;
        }

        private TreeViewItem MakeLeaf(string key, string value)
        {
            var tb = new TextBlock { FontFamily = new FontFamily("Consolas") };
            if (key != null)
            {
                tb.Inlines.Add(new System.Windows.Documents.Run($"  {key}: ")
                    { Foreground = new SolidColorBrush(Color.FromRgb(0, 85, 0)) });
                tb.Inlines.Add(new System.Windows.Documents.Run(value ?? "")
                    { Foreground = new SolidColorBrush(Color.FromRgb(0, 200, 0)) });
            }
            else
            {
                tb.Inlines.Add(new System.Windows.Documents.Run($"  {value}")
                    { Foreground = new SolidColorBrush(Color.FromRgb(0, 136, 0)), FontSize = 10 });
            }

            return new TreeViewItem
            {
                Header = tb,
                Tag = key != null ? $"{key}: {value}" : value
            };
        }

        private void CopyValue_Click(object sender, RoutedEventArgs e)
        {
            if (PacketTree.SelectedItem is TreeViewItem item)
            {
                var text = item.Tag as string;
                if (text == null && item.Header is TextBlock tb)
                    text = tb.Text;
                if (text != null)
                    Clipboard.SetText(text);
            }
        }

        private void CopyBranch_Click(object sender, RoutedEventArgs e)
        {
            if (PacketTree.SelectedItem is TreeViewItem item)
            {
                var sb = new StringBuilder();
                CollectBranch(item, sb, 0);
                Clipboard.SetText(sb.ToString());
            }
        }

        private void CopyAll_Click(object sender, RoutedEventArgs e)
        {
            var sb = new StringBuilder();
            sb.AppendLine($"=== PACKET: {_entry.Summary} ===");
            sb.AppendLine($"Status: {_entry.StatusText}");
            sb.AppendLine($"Time: {_entry.Timestamp:yyyy-MM-dd HH:mm:ss.fff}");
            sb.AppendLine();

            foreach (var obj in PacketTree.Items)
            {
                if (obj is TreeViewItem item)
                    CollectBranch(item, sb, 0);
            }

            sb.AppendLine();
            sb.AppendLine("=== HEX DUMP ===");
            sb.AppendLine(_entry.PacketHexDump);

            Clipboard.SetText(sb.ToString());
        }

        private void CollectBranch(TreeViewItem item, StringBuilder sb, int depth)
        {
            var prefix = new string(' ', depth * 2);
            if (item.Tag is string tagText)
                sb.AppendLine($"{prefix}{tagText}");
            else if (item.Header is TextBlock tb)
                sb.AppendLine($"{prefix}{tb.Text}");
            else if (item.Header is string s)
                sb.AppendLine($"{prefix}{s}");

            foreach (var child in item.Items)
            {
                if (child is TreeViewItem childItem)
                    CollectBranch(childItem, sb, depth + 1);
            }
        }
    }
}
