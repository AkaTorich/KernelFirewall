using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using CommunityToolkit.Mvvm.ComponentModel;

namespace FirewallController.Models
{
    public enum FirewallAction
    {
        Block = 0,
        Allow = 1,
        AllowRestricted = 2
    }

    public enum TrafficDirection
    {
        Any = 0,           // Match any direction (input + output)
        Input = 1,         // Match incoming traffic (remote -> local)
        Output = 2         // Match outgoing traffic (local -> remote)
    }

    [StructLayout(LayoutKind.Sequential, Pack = 2, CharSet = CharSet.Unicode)]
    public struct PortRange
    {
        public ushort StartPort;
        public ushort EndPort;

        public override string ToString()
        {
            return StartPort == EndPort ? StartPort.ToString() : $"{StartPort}-{EndPort}";
        }
    }

    // Unified IP address structure supporting both IPv4 and IPv6
    [StructLayout(LayoutKind.Explicit, Size = 48)]
    public struct IpAddressEntry
    {
        // Address family field (2 = IPv4, 23 = IPv6)
        [FieldOffset(0)]
        public ushort AddressFamily;

        [FieldOffset(2)]
        public ushort Reserved;

        // IPv4 fields
        [FieldOffset(4)]
        public uint AddressV4;

        [FieldOffset(8)]
        public uint MaskV4;

        // IPv6 fields - EXPLICITLY DEFINED (NOT managed array!)
        [FieldOffset(4)] public byte IPv6_Byte0;
        [FieldOffset(5)] public byte IPv6_Byte1;
        [FieldOffset(6)] public byte IPv6_Byte2;
        [FieldOffset(7)] public byte IPv6_Byte3;
        [FieldOffset(8)] public byte IPv6_Byte4;
        [FieldOffset(9)] public byte IPv6_Byte5;
        [FieldOffset(10)] public byte IPv6_Byte6;
        [FieldOffset(11)] public byte IPv6_Byte7;
        [FieldOffset(12)] public byte IPv6_Byte8;
        [FieldOffset(13)] public byte IPv6_Byte9;
        [FieldOffset(14)] public byte IPv6_Byte10;
        [FieldOffset(15)] public byte IPv6_Byte11;
        [FieldOffset(16)] public byte IPv6_Byte12;
        [FieldOffset(17)] public byte IPv6_Byte13;
        [FieldOffset(18)] public byte IPv6_Byte14;
        [FieldOffset(19)] public byte IPv6_Byte15;

        [FieldOffset(20)]
        public byte PrefixLengthV6;

        // Helper properties
        public bool IsIPv4 => AddressFamily == 2;
        public bool IsIPv6 => AddressFamily == 23;

        // Convert to IP string representation
        public string ToIpString()
        {
            if (IsIPv4)
            {
                byte[] bytes = BitConverter.GetBytes(AddressV4);
                return $"{bytes[3]}.{bytes[2]}.{bytes[1]}.{bytes[0]}";
            }
            else if (IsIPv6)
            {
                byte[] ipv6Bytes = new byte[16];
                ipv6Bytes[0] = IPv6_Byte0; ipv6Bytes[1] = IPv6_Byte1;
                ipv6Bytes[2] = IPv6_Byte2; ipv6Bytes[3] = IPv6_Byte3;
                ipv6Bytes[4] = IPv6_Byte4; ipv6Bytes[5] = IPv6_Byte5;
                ipv6Bytes[6] = IPv6_Byte6; ipv6Bytes[7] = IPv6_Byte7;
                ipv6Bytes[8] = IPv6_Byte8; ipv6Bytes[9] = IPv6_Byte9;
                ipv6Bytes[10] = IPv6_Byte10; ipv6Bytes[11] = IPv6_Byte11;
                ipv6Bytes[12] = IPv6_Byte12; ipv6Bytes[13] = IPv6_Byte13;
                ipv6Bytes[14] = IPv6_Byte14; ipv6Bytes[15] = IPv6_Byte15;
                var ipv6 = new IPAddress(ipv6Bytes);
                return ipv6.ToString();
            }
            return "Unknown";
        }

        // Parse IP address from string (supports both IPv4 and IPv6)
        // Formats: "192.168.1.1/24", "192.168.1.1/255.255.255.0", "2001:db8::1/64", "2001:db8::1"
        public static IpAddressEntry FromString(string input)
        {
            var entry = new IpAddressEntry();

            if (string.IsNullOrWhiteSpace(input))
            {
                // Default to IPv4
                entry.AddressFamily = 2;
                entry.AddressV4 = 0;
                entry.MaskV4 = 0xFFFFFFFF;
                return entry;
            }

            // Check if this is IPv6 (contains ':')
            if (input.Contains(':'))
            {
                // IPv6
                entry.AddressFamily = 23;

                var parts = input.Split('/');
                var addr = parts[0];

                // Parse IPv6 address
                if (IPAddress.TryParse(addr, out var ipv6) && ipv6.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
                {
                    byte[] bytes = ipv6.GetAddressBytes();
                    entry.IPv6_Byte0 = bytes[0]; entry.IPv6_Byte1 = bytes[1];
                    entry.IPv6_Byte2 = bytes[2]; entry.IPv6_Byte3 = bytes[3];
                    entry.IPv6_Byte4 = bytes[4]; entry.IPv6_Byte5 = bytes[5];
                    entry.IPv6_Byte6 = bytes[6]; entry.IPv6_Byte7 = bytes[7];
                    entry.IPv6_Byte8 = bytes[8]; entry.IPv6_Byte9 = bytes[9];
                    entry.IPv6_Byte10 = bytes[10]; entry.IPv6_Byte11 = bytes[11];
                    entry.IPv6_Byte12 = bytes[12]; entry.IPv6_Byte13 = bytes[13];
                    entry.IPv6_Byte14 = bytes[14]; entry.IPv6_Byte15 = bytes[15];
                }

                // Parse prefix length
                if (parts.Length > 1 && byte.TryParse(parts[1], out byte prefix) && prefix <= 128)
                {
                    entry.PrefixLengthV6 = prefix;
                }
                else
                {
                    entry.PrefixLengthV6 = 128; // Full address
                }
            }
            else
            {
                // IPv4
                entry.AddressFamily = 2;

                var parts = input.Split('/');
                var addr = parts[0].Split('.');

                // Parse IPv4 address
                if (addr.Length == 4)
                {
                    entry.AddressV4 = (uint)((byte.Parse(addr[0]) << 24) |
                                           (byte.Parse(addr[1]) << 16) |
                                           (byte.Parse(addr[2]) << 8) |
                                           byte.Parse(addr[3]));
                }
                else
                {
                    entry.AddressV4 = 0;
                }

                // Parse mask/prefix
                if (parts.Length > 1)
                {
                    // Check if it's CIDR notation or subnet mask
                    if (parts[1].Contains('.'))
                    {
                        // Subnet mask format (e.g., "255.255.255.0")
                        var maskParts = parts[1].Split('.');
                        if (maskParts.Length == 4)
                        {
                            entry.MaskV4 = (uint)((byte.Parse(maskParts[0]) << 24) |
                                                (byte.Parse(maskParts[1]) << 16) |
                                                (byte.Parse(maskParts[2]) << 8) |
                                                byte.Parse(maskParts[3]));
                        }
                        else
                        {
                            entry.MaskV4 = 0xFFFFFFFF;
                        }
                    }
                    else
                    {
                        // CIDR prefix length (e.g., "/24")
                        if (int.TryParse(parts[1], out int prefix) && prefix >= 0 && prefix <= 32)
                        {
                            entry.MaskV4 = prefix == 0 ? 0 : (0xFFFFFFFF << (32 - prefix));
                        }
                        else
                        {
                            entry.MaskV4 = 0xFFFFFFFF;
                        }
                    }
                }
                else
                {
                    entry.MaskV4 = 0xFFFFFFFF; // Full host (/32)
                }
            }

            return entry;
        }

        // Backward compatibility: FromString with separate mask parameter (IPv4 only)
        public static IpAddressEntry FromString(string ip, string mask)
        {
            var entry = new IpAddressEntry();
            entry.AddressFamily = 2;

            var parts = ip.Split('.');
            if (parts.Length == 4)
            {
                entry.AddressV4 = (uint)((byte.Parse(parts[0]) << 24) |
                                       (byte.Parse(parts[1]) << 16) |
                                       (byte.Parse(parts[2]) << 8) |
                                       byte.Parse(parts[3]));
            }

            var maskParts = mask.Split('.');
            if (maskParts.Length == 4)
            {
                entry.MaskV4 = (uint)((byte.Parse(maskParts[0]) << 24) |
                                    (byte.Parse(maskParts[1]) << 16) |
                                    (byte.Parse(maskParts[2]) << 8) |
                                    byte.Parse(maskParts[3]));
            }
            else
            {
                entry.MaskV4 = 0xFFFFFFFF;
            }

            return entry;
        }

        // ToString with CIDR notation
        public override string ToString()
        {
            if (IsIPv4)
            {
                string ip = ToIpString();
                int cidr = CountMaskBits(MaskV4);
                return $"{ip}/{cidr}";
            }
            else if (IsIPv6)
            {
                string ip = ToIpString();
                return $"{ip}/{PrefixLengthV6}";
            }
            return "Unknown";
        }

        // Count number of set bits in IPv4 mask
        private static int CountMaskBits(uint mask)
        {
            int count = 0;
            for (int i = 0; i < 32; i++)
            {
                if ((mask & (1u << i)) != 0)
                    count++;
            }
            return count;
        }
    }

    public partial class FirewallRule : ObservableObject
    {
        [ObservableProperty] private uint _ruleId;
        [ObservableProperty] private string _applicationPath = "";
        [ObservableProperty] private string _applicationName = "";
        [ObservableProperty] private uint _processId;  // 0 = match by path, non-zero = match by PID
        [ObservableProperty] private FirewallAction _action = FirewallAction.Block;
        [ObservableProperty] private TrafficDirection _direction = TrafficDirection.Output;  // Default to Output for outgoing traffic
        [ObservableProperty] private List<PortRange> _portRanges = new();
        [ObservableProperty] private List<IpAddressEntry> _ipAddresses = new();
        [ObservableProperty] private bool _isActive = true;

        public string ActionDisplay => Action switch
        {
            FirewallAction.Block => "🛑 Блок",
            FirewallAction.Allow => "✅ Разрешить",
            FirewallAction.AllowRestricted => "🔒 Ограничить",
            _ => "?"
        };

        public string DirectionDisplay => Direction switch
        {
            TrafficDirection.Any => "Любой",
            TrafficDirection.Input => "Input (входящий)",
            TrafficDirection.Output => "Output (исходящий)",
            _ => "?"
        };

        public string PortsDisplay => PortRanges.Count == 0 ? "Все" : string.Join(", ", PortRanges);
        public string IpsDisplay => IpAddresses.Count == 0 ? "Все" : string.Join(", ", IpAddresses.ConvertAll(ip => ip.ToIpString()));
    }

    public partial class BlockedApp : ObservableObject
    {
        [ObservableProperty] private string _applicationPath = "";
        [ObservableProperty] private string _applicationName = "";
        [ObservableProperty] private uint _processId;
        [ObservableProperty] private bool _isBlocked = true;
    }

    public partial class ProcessInfo : ObservableObject
    {
        [ObservableProperty] private uint _processId;
        [ObservableProperty] private string _processName = "";
        [ObservableProperty] private string _executablePath = "";
        [ObservableProperty] private bool _isSelected;
        [ObservableProperty] private bool _isBlocked;

        public string DisplayName => string.IsNullOrEmpty(ProcessName) ? $"PID: {ProcessId}" : ProcessName;

        // Check if this is a PID-based entry (no real path)
        public bool IsPidBased => !string.IsNullOrEmpty(ExecutablePath) &&
                                   ExecutablePath.StartsWith("PID:");

        // Can this process be blocked by the firewall?
        public bool CanBeBlocked => !string.IsNullOrEmpty(ExecutablePath) && !IsBlocked;
    }

    public class FirewallStatus
    {
        public bool IsEnabled { get; set; }
        public uint RuleCount { get; set; }
        public uint BlockedAppCount { get; set; }
        public uint PacketsBlocked { get; set; }
        public uint PacketsAllowed { get; set; }
    }
}

