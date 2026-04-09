using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using HackerFirewall.Infrastructure;

namespace HackerFirewall.Models
{
    public enum FirewallAction
    {
        Block = 0,
        Allow = 1,
        AllowRestricted = 2
    }

    public enum TrafficDirection
    {
        Any = 0,
        Input = 1,
        Output = 2
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

    [StructLayout(LayoutKind.Explicit, Size = 48)]
    public struct IpAddressEntry
    {
        [FieldOffset(0)] public ushort AddressFamily;
        [FieldOffset(2)] public ushort Reserved;

        [FieldOffset(4)] public uint AddressV4;
        [FieldOffset(8)] public uint MaskV4;

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

        [FieldOffset(20)] public byte PrefixLengthV6;

        public bool IsIPv4 => AddressFamily == 2;
        public bool IsIPv6 => AddressFamily == 23;

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

        public static IpAddressEntry FromString(string input)
        {
            var entry = new IpAddressEntry();

            if (string.IsNullOrWhiteSpace(input))
            {
                entry.AddressFamily = 2;
                entry.AddressV4 = 0;
                entry.MaskV4 = 0xFFFFFFFF;
                return entry;
            }

            if (input.Contains(":"))
            {
                entry.AddressFamily = 23;
                var parts = input.Split('/');
                var addr = parts[0];

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

                if (parts.Length > 1 && byte.TryParse(parts[1], out byte prefix) && prefix <= 128)
                    entry.PrefixLengthV6 = prefix;
                else
                    entry.PrefixLengthV6 = 128;
            }
            else
            {
                entry.AddressFamily = 2;
                var parts = input.Split('/');
                var addr = parts[0].Split('.');

                if (addr.Length == 4)
                {
                    entry.AddressV4 = (uint)((byte.Parse(addr[0]) << 24) |
                                             (byte.Parse(addr[1]) << 16) |
                                             (byte.Parse(addr[2]) << 8) |
                                             byte.Parse(addr[3]));
                }

                if (parts.Length > 1)
                {
                    if (parts[1].Contains("."))
                    {
                        var maskParts = parts[1].Split('.');
                        if (maskParts.Length == 4)
                        {
                            entry.MaskV4 = (uint)((byte.Parse(maskParts[0]) << 24) |
                                                  (byte.Parse(maskParts[1]) << 16) |
                                                  (byte.Parse(maskParts[2]) << 8) |
                                                  byte.Parse(maskParts[3]));
                        }
                        else
                            entry.MaskV4 = 0xFFFFFFFF;
                    }
                    else
                    {
                        if (int.TryParse(parts[1], out int pfx) && pfx >= 0 && pfx <= 32)
                            entry.MaskV4 = pfx == 0 ? 0 : (0xFFFFFFFF << (32 - pfx));
                        else
                            entry.MaskV4 = 0xFFFFFFFF;
                    }
                }
                else
                {
                    entry.MaskV4 = 0xFFFFFFFF;
                }
            }

            return entry;
        }

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
                entry.MaskV4 = 0xFFFFFFFF;

            return entry;
        }

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

    public class FirewallRule : ViewModelBase
    {
        private uint _ruleId;
        public uint RuleId { get => _ruleId; set => SetProperty(ref _ruleId, value); }

        private string _applicationPath = "";
        public string ApplicationPath { get => _applicationPath; set => SetProperty(ref _applicationPath, value); }

        private string _applicationName = "";
        public string ApplicationName { get => _applicationName; set => SetProperty(ref _applicationName, value); }

        private uint _processId;
        public uint ProcessId { get => _processId; set => SetProperty(ref _processId, value); }

        private FirewallAction _action = FirewallAction.Block;
        public FirewallAction Action { get => _action; set => SetProperty(ref _action, value); }

        private TrafficDirection _direction = TrafficDirection.Output;
        public TrafficDirection Direction { get => _direction; set => SetProperty(ref _direction, value); }

        private List<PortRange> _portRanges = new List<PortRange>();
        public List<PortRange> PortRanges { get => _portRanges; set => SetProperty(ref _portRanges, value); }

        private List<IpAddressEntry> _ipAddresses = new List<IpAddressEntry>();
        public List<IpAddressEntry> IpAddresses { get => _ipAddresses; set => SetProperty(ref _ipAddresses, value); }

        private bool _isActive = true;
        public bool IsActive { get => _isActive; set => SetProperty(ref _isActive, value); }

        public string ActionDisplay => Action switch
        {
            FirewallAction.Block => "[BLOCK]",
            FirewallAction.Allow => "[ALLOW]",
            FirewallAction.AllowRestricted => "[RESTRICT]",
            _ => "[?]"
        };

        public string DirectionDisplay => Direction switch
        {
            TrafficDirection.Any => "ANY",
            TrafficDirection.Input => "IN",
            TrafficDirection.Output => "OUT",
            _ => "?"
        };

        public string PortsDisplay => PortRanges.Count == 0 ? "*" : string.Join(", ", PortRanges);
        public string IpsDisplay => IpAddresses.Count == 0 ? "*" : string.Join(", ", IpAddresses.ConvertAll(ip => ip.ToIpString()));
    }

    public class BlockedApp : ViewModelBase
    {
        private string _applicationPath = "";
        public string ApplicationPath { get => _applicationPath; set => SetProperty(ref _applicationPath, value); }

        private string _applicationName = "";
        public string ApplicationName { get => _applicationName; set => SetProperty(ref _applicationName, value); }

        private uint _processId;
        public uint ProcessId { get => _processId; set => SetProperty(ref _processId, value); }

        private bool _isBlocked = true;
        public bool IsBlocked { get => _isBlocked; set => SetProperty(ref _isBlocked, value); }
    }

    public class ProcessInfo : ViewModelBase
    {
        private uint _processId;
        public uint ProcessId { get => _processId; set => SetProperty(ref _processId, value); }

        private string _processName = "";
        public string ProcessName { get => _processName; set => SetProperty(ref _processName, value); }

        private string _executablePath = "";
        public string ExecutablePath { get => _executablePath; set => SetProperty(ref _executablePath, value); }

        private bool _isSelected;
        public bool IsSelected { get => _isSelected; set => SetProperty(ref _isSelected, value); }

        private bool _isBlocked;
        public bool IsBlocked { get => _isBlocked; set => SetProperty(ref _isBlocked, value); }

        private uint _packetsSent;
        public uint PacketsSent
        {
            get => _packetsSent;
            set { if (SetProperty(ref _packetsSent, value)) OnPropertyChanged(nameof(TrafficDisplay)); }
        }

        private uint _packetsRecv;
        public uint PacketsRecv
        {
            get => _packetsRecv;
            set { if (SetProperty(ref _packetsRecv, value)) OnPropertyChanged(nameof(TrafficDisplay)); }
        }

        private uint _packetsBlockedCount;
        public uint PacketsBlockedCount
        {
            get => _packetsBlockedCount;
            set { if (SetProperty(ref _packetsBlockedCount, value)) OnPropertyChanged(nameof(TrafficDisplay)); }
        }

        public string TrafficDisplay => $"OUT:{PacketsSent} IN:{PacketsRecv} BLK:{PacketsBlockedCount}";

        public string DisplayName => string.IsNullOrEmpty(ProcessName) ? $"PID: {ProcessId}" : ProcessName;
        public bool IsPidBased => !string.IsNullOrEmpty(ExecutablePath) && ExecutablePath.StartsWith("PID:");
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
