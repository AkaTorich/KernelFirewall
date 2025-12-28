using System;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Text;
using CommunityToolkit.Mvvm.ComponentModel;

namespace FirewallController.Models
{
    // ARP table helper
    public static class ArpHelper
    {
        [DllImport("iphlpapi.dll", ExactSpelling = true)]
        private static extern int GetIpNetTable(IntPtr pIpNetTable, ref int pdwSize, bool bOrder);

        [StructLayout(LayoutKind.Sequential)]
        private struct MIB_IPNETROW
        {
            public int dwIndex;
            public int dwPhysAddrLen;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public byte[] bPhysAddr;
            public uint dwAddr;
            public int dwType;
        }

        public static string GetMacFromIp(string ipAddress)
        {
            try
            {
                int bytesNeeded = 0;
                GetIpNetTable(IntPtr.Zero, ref bytesNeeded, false);
                
                IntPtr buffer = Marshal.AllocCoTaskMem(bytesNeeded);
                try
                {
                    if (GetIpNetTable(buffer, ref bytesNeeded, false) != 0)
                        return null!;

                    int entries = Marshal.ReadInt32(buffer);
                    IntPtr currentBuffer = buffer + 4;

                    var parts = ipAddress.Split('.');
                    if (parts.Length != 4) return null!;
                    uint targetIp = (uint)(int.Parse(parts[0]) | (int.Parse(parts[1]) << 8) | 
                                          (int.Parse(parts[2]) << 16) | (int.Parse(parts[3]) << 24));

                    for (int i = 0; i < entries; i++)
                    {
                        var row = Marshal.PtrToStructure<MIB_IPNETROW>(currentBuffer);
                        if (row.dwAddr == targetIp && row.dwPhysAddrLen > 0)
                        {
                            return string.Format("{0:X2}:{1:X2}:{2:X2}:{3:X2}:{4:X2}:{5:X2}",
                                row.bPhysAddr[0], row.bPhysAddr[1], row.bPhysAddr[2],
                                row.bPhysAddr[3], row.bPhysAddr[4], row.bPhysAddr[5]);
                        }
                        currentBuffer += Marshal.SizeOf<MIB_IPNETROW>();
                    }
                }
                finally
                {
                    Marshal.FreeCoTaskMem(buffer);
                }
            }
            catch { }
            return "N/A";
        }

        private static string? _cachedLocalMac = null;
        
        public static string GetLocalMac()
        {
            if (_cachedLocalMac != null) return _cachedLocalMac;
            
            try
            {
                foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (nic.NetworkInterfaceType == NetworkInterfaceType.Loopback ||
                        nic.NetworkInterfaceType == NetworkInterfaceType.Tunnel)
                        continue;
                    
                    var mac = nic.GetPhysicalAddress().GetAddressBytes();
                    if (mac.Length >= 6 && (mac[0] != 0 || mac[1] != 0 || mac[2] != 0))
                    {
                        _cachedLocalMac = string.Format("{0:X2}:{1:X2}:{2:X2}:{3:X2}:{4:X2}:{5:X2}",
                            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
                        return _cachedLocalMac;
                    }
                }
            }
            catch { }
            return "N/A";
        }
    }

    public enum PacketDirection
    {
        Outbound = 0,
        Inbound = 1
    }

    public enum ProtocolType
    {
        Other = 0,
        ICMP = 1,
        TCP = 6,
        UDP = 17
    }

    public partial class TrafficEntry : ObservableObject
    {
        [ObservableProperty] private DateTime _timestamp;
        [ObservableProperty] private uint _processId;
        [ObservableProperty] private string _processName = "";
        [ObservableProperty] private string _localAddress = "";
        [ObservableProperty] private string _remoteAddress = "";
        [ObservableProperty] private ProtocolType _protocol;
        [ObservableProperty] private PacketDirection _direction;
        [ObservableProperty] private bool _wasBlocked;
        [ObservableProperty] private uint _dataSize;
        [ObservableProperty] private string _localIpOnly = "";
        [ObservableProperty] private ushort _localPortOnly;
        [ObservableProperty] private string _remoteIpOnly = "";
        [ObservableProperty] private ushort _remotePortOnly;
        [ObservableProperty] private byte[] _packetData = Array.Empty<byte>();
        [ObservableProperty] private string _ipVersion = "IPv4";

        // Auto-detect IP version when LocalIpOnly changes
        partial void OnLocalIpOnlyChanged(string value)
        {
            IpVersion = !string.IsNullOrEmpty(value) && value.Contains(':') ? "IPv6" : "IPv4";
        }

        public string DirectionArrow => Direction == PacketDirection.Outbound ? "→" : "←";
        public string DirectionText => Direction == PacketDirection.Outbound ? "OUT" : "IN";
        
        public string ProtocolText => Protocol switch
        {
            ProtocolType.TCP => "TCP",
            ProtocolType.UDP => "UDP",
            _ => "???"
        };

        public string StatusText => WasBlocked ? "🛑 BLOCKED" : "✅ ALLOWED";
        
        public string Summary => Direction == PacketDirection.Outbound
            ? $"{LocalAddress} → {RemoteAddress}"
            : $"{LocalAddress} ← {RemoteAddress}";

        public string IpProtocolInfo => Protocol switch
        {
            ProtocolType.TCP => "6 (TCP)",
            ProtocolType.UDP => "17 (UDP)",
            _ => $"{(int)Protocol} (Unknown)"
        };

        public string UtcOffset => TimeZoneInfo.Local.GetUtcOffset(Timestamp).ToString(@"hh\:mm");

        public string ServiceGuess
        {
            get
            {
                var port = Direction == PacketDirection.Outbound ? RemotePortOnly : LocalPortOnly;
                return port switch
                {
                    20 or 21 => "FTP",
                    22 => "SSH",
                    23 => "Telnet",
                    25 => "SMTP",
                    53 => "DNS",
                    67 or 68 => "DHCP",
                    80 => "HTTP",
                    110 => "POP3",
                    123 => "NTP",
                    137 or 138 or 139 => "NetBIOS",
                    143 => "IMAP",
                    161 or 162 => "SNMP",
                    389 => "LDAP",
                    443 => "HTTPS",
                    445 => "SMB",
                    465 or 587 => "SMTP/TLS",
                    993 => "IMAPS",
                    995 => "POP3S",
                    1433 => "MSSQL",
                    1900 => "SSDP",
                    3306 => "MySQL",
                    3389 => "RDP",
                    5353 => "mDNS",
                    5355 => "LLMNR",
                    5432 => "PostgreSQL",
                    8080 => "HTTP Proxy",
                    _ => port > 1024 ? "Application" : "System"
                };
            }
        }

        public string FullDetails => 
            $"Время: {Timestamp:HH:mm:ss.fff}\n" +
            $"Процесс: {ProcessName} (PID: {ProcessId})\n" +
            $"Протокол: {ProtocolText}\n" +
            $"Направление: {(Direction == PacketDirection.Outbound ? "Исходящий" : "Входящий")}\n" +
            $"Локальный: {LocalAddress}\n" +
            $"Удалённый: {RemoteAddress}\n" +
            $"Статус: {(WasBlocked ? "Заблокирован" : "Разрешён")}";

        public string IpVersionHeader => IpVersion;
        public string EtherType => IpVersion == "IPv6" ? "0x86DD (IPv6)" : "0x0800 (IPv4)";

        // Hex dump with ASCII
        public string PacketHexDump
        {
            get
            {
                if (PacketData == null || PacketData.Length == 0) 
                    return "(no payload data)";
                
                var sb = new StringBuilder();
                int rows = (PacketData.Length + 15) / 16;
                
                for (int row = 0; row < rows; row++)
                {
                    int offset = row * 16;
                    sb.Append($"{offset:X4}  ");
                    
                    for (int col = 0; col < 16; col++)
                    {
                        if (col == 8) sb.Append(" ");
                        int idx = offset + col;
                        if (idx < PacketData.Length)
                            sb.Append($"{PacketData[idx]:X2} ");
                        else
                            sb.Append("   ");
                    }
                    
                    sb.Append(" │ ");
                    
                    for (int col = 0; col < 16; col++)
                    {
                        int idx = offset + col;
                        if (idx < PacketData.Length)
                        {
                            byte b = PacketData[idx];
                            sb.Append(b >= 32 && b < 127 ? (char)b : '.');
                        }
                    }
                    
                    if (row < rows - 1) sb.AppendLine();
                }
                
                return sb.ToString();
            }
        }

        public int PacketDataLength => PacketData?.Length ?? 0;

        public string SourceMac
        {
            get
            {
                if (Direction == PacketDirection.Outbound)
                    return ArpHelper.GetLocalMac();
                else
                    return ArpHelper.GetMacFromIp(RemoteIpOnly);
            }
        }

        public string DestinationMac
        {
            get
            {
                if (Direction == PacketDirection.Outbound)
                    return ArpHelper.GetMacFromIp(RemoteIpOnly);
                else
                    return ArpHelper.GetLocalMac();
            }
        }

        private string? _processPath;

        public string PathLanguage
        {
            get
            {
                try
                {
                    // Get process path if not already cached
                    if (_processPath == null && ProcessId > 0)
                    {
                        var processService = new Services.ProcessService();
                        _processPath = processService.GetProcessPath((int)ProcessId) ?? ProcessName;
                    }

                    var path = _processPath ?? ProcessName ?? "";

                    // Check for invalid patterns
                    if (string.IsNullOrWhiteSpace(path))
                        return "";

                    // Check for more than one space in a row
                    if (path.Contains("  "))
                        return "";

                    // Check for two or more dots in a row
                    if (path.Contains(".."))
                        return "";

                    // Check for commas in a row (even single comma is suspicious in path)
                    if (path.Contains(","))
                        return "";

                    // Check if this is a duplicate process (same name, different path)
                    if (!string.IsNullOrWhiteSpace(ProcessName))
                    {
                        var processRegistry = Services.ProcessRegistryService.Instance;
                        if (processRegistry.IsDuplicate(ProcessName, path))
                        {
                            return "дубликат";
                        }
                    }

                    // Analyze characters
                    bool hasRussian = false;
                    bool hasEnglish = false;
                    bool hasOther = false;

                    foreach (char c in path)
                    {
                        // Skip common path characters
                        if (char.IsWhiteSpace(c) || c == '\\' || c == '/' || c == ':' ||
                            c == '.' || c == '-' || c == '_' || char.IsDigit(c))
                            continue;

                        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'))
                        {
                            hasEnglish = true;
                        }
                        else if ((c >= '\u0400' && c <= '\u04FF') || // Cyrillic block
                                 (c >= '\u0500' && c <= '\u052F'))   // Cyrillic Supplement
                        {
                            hasRussian = true;
                        }
                        else
                        {
                            hasOther = true;
                        }
                    }

                    // If has other languages, return empty
                    if (hasOther)
                        return "";

                    // If has both Russian and English, return empty (mixed)
                    if (hasRussian && hasEnglish)
                        return "";

                    if (hasRussian)
                        return "русский";

                    if (hasEnglish)
                        return "английский";

                    return "";
                }
                catch
                {
                    return "";
                }
            }
        }
    }
}
