using System;
using System.Runtime.InteropServices;
using FirewallController.Models;
using Microsoft.Win32.SafeHandles;

namespace FirewallController.Services
{
    public class DriverService : IDisposable
    {
        private const string DevicePath = @"\\.\KernelFirewall";
        
        // IOCTL codes (must match driver)
        private const uint IOCTL_BASE = 0x8000;
        private static readonly uint IOCTL_FIREWALL_ADD_RULE = CTL_CODE(IOCTL_BASE, 0x800);
        private static readonly uint IOCTL_FIREWALL_REMOVE_RULE = CTL_CODE(IOCTL_BASE, 0x801);
        private static readonly uint IOCTL_FIREWALL_CLEAR_RULES = CTL_CODE(IOCTL_BASE, 0x802);
        private static readonly uint IOCTL_FIREWALL_GET_RULES = CTL_CODE(IOCTL_BASE, 0x803);
        private static readonly uint IOCTL_FIREWALL_ENABLE = CTL_CODE(IOCTL_BASE, 0x804);
        private static readonly uint IOCTL_FIREWALL_DISABLE = CTL_CODE(IOCTL_BASE, 0x805);
        private static readonly uint IOCTL_FIREWALL_GET_STATUS = CTL_CODE(IOCTL_BASE, 0x806);
        private static readonly uint IOCTL_FIREWALL_BLOCK_APP = CTL_CODE(IOCTL_BASE, 0x807);
        private static readonly uint IOCTL_FIREWALL_UNBLOCK_APP = CTL_CODE(IOCTL_BASE, 0x808);
        private static readonly uint IOCTL_FIREWALL_GET_BLOCKED = CTL_CODE(IOCTL_BASE, 0x809);
        private static readonly uint IOCTL_FIREWALL_SET_MONITOR = CTL_CODE(IOCTL_BASE, 0x80C);
        private static readonly uint IOCTL_FIREWALL_GET_ETW_GUID = CTL_CODE(IOCTL_BASE, 0x80D);

        private SafeFileHandle? _deviceHandle;
        private bool _disposed;

        private static uint CTL_CODE(uint deviceType, uint function)
        {
            return (deviceType << 16) | (0 << 14) | (function << 2) | 0;
        }

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern SafeFileHandle CreateFile(
            string lpFileName,
            uint dwDesiredAccess,
            uint dwShareMode,
            IntPtr lpSecurityAttributes,
            uint dwCreationDisposition,
            uint dwFlagsAndAttributes,
            IntPtr hTemplateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool DeviceIoControl(
            SafeFileHandle hDevice,
            uint dwIoControlCode,
            IntPtr lpInBuffer,
            uint nInBufferSize,
            IntPtr lpOutBuffer,
            uint nOutBufferSize,
            out uint lpBytesReturned,
            IntPtr lpOverlapped);

        public bool Connect()
        {
            if (_deviceHandle != null && !_deviceHandle.IsInvalid)
                return true;

            _deviceHandle = CreateFile(
                DevicePath,
                0xC0000000, // GENERIC_READ | GENERIC_WRITE
                0,
                IntPtr.Zero,
                3, // OPEN_EXISTING
                0,
                IntPtr.Zero);

            return !_deviceHandle.IsInvalid;
        }

        public bool IsConnected => _deviceHandle != null && !_deviceHandle.IsInvalid;

        public FirewallStatus? GetStatus()
        {
            if (!IsConnected) return null;

            var outputSize = Marshal.SizeOf<NativeFirewallStatus>();
            var outputPtr = Marshal.AllocHGlobal(outputSize);

            try
            {
                if (DeviceIoControl(_deviceHandle!, IOCTL_FIREWALL_GET_STATUS,
                    IntPtr.Zero, 0, outputPtr, (uint)outputSize, out _, IntPtr.Zero))
                {
                    var native = Marshal.PtrToStructure<NativeFirewallStatus>(outputPtr);
                    return new FirewallStatus
                    {
                        IsEnabled = native.IsEnabled != 0,
                        RuleCount = native.RuleCount,
                        BlockedAppCount = native.BlockedAppCount,
                        PacketsBlocked = native.PacketsBlocked,
                        PacketsAllowed = native.PacketsAllowed
                    };
                }
            }
            finally
            {
                Marshal.FreeHGlobal(outputPtr);
            }

            return null;
        }

        public bool EnableFirewall()
        {
            if (!IsConnected) return false;
            return DeviceIoControl(_deviceHandle!, IOCTL_FIREWALL_ENABLE,
                IntPtr.Zero, 0, IntPtr.Zero, 0, out _, IntPtr.Zero);
        }

        public bool DisableFirewall()
        {
            if (!IsConnected) return false;
            return DeviceIoControl(_deviceHandle!, IOCTL_FIREWALL_DISABLE,
                IntPtr.Zero, 0, IntPtr.Zero, 0, out _, IntPtr.Zero);
        }

        public bool BlockApp(string applicationPath, uint processId = 0)
        {
            if (!IsConnected) return false;

            var request = new NativeBlockAppRequest
            {
                ApplicationPath = applicationPath,
                ProcessId = processId
            };

            var inputSize = Marshal.SizeOf<NativeBlockAppRequest>();
            var inputPtr = Marshal.AllocHGlobal(inputSize);

            try
            {
                Marshal.StructureToPtr(request, inputPtr, false);
                return DeviceIoControl(_deviceHandle!, IOCTL_FIREWALL_BLOCK_APP,
                    inputPtr, (uint)inputSize, IntPtr.Zero, 0, out _, IntPtr.Zero);
            }
            finally
            {
                Marshal.FreeHGlobal(inputPtr);
            }
        }

        public bool UnblockApp(string applicationPath)
        {
            if (!IsConnected) return false;

            var request = new NativeBlockAppRequest
            {
                ApplicationPath = applicationPath,
                ProcessId = 0
            };

            var inputSize = Marshal.SizeOf<NativeBlockAppRequest>();
            var inputPtr = Marshal.AllocHGlobal(inputSize);

            try
            {
                Marshal.StructureToPtr(request, inputPtr, false);
                return DeviceIoControl(_deviceHandle!, IOCTL_FIREWALL_UNBLOCK_APP,
                    inputPtr, (uint)inputSize, IntPtr.Zero, 0, out _, IntPtr.Zero);
            }
            finally
            {
                Marshal.FreeHGlobal(inputPtr);
            }
        }

        public bool AddRule(FirewallRule rule)
        {
            if (!IsConnected) return false;

            var nativeRule = new NativeFirewallRule
            {
                RuleId = rule.RuleId,
                ApplicationPath = rule.ApplicationPath,
                ProcessId = rule.ProcessId,
                Action = (uint)rule.Action,
                Direction = (uint)rule.Direction,
                PortRangeCount = (uint)Math.Min(rule.PortRanges.Count, 32),
                IpAddressCount = (uint)Math.Min(rule.IpAddresses.Count, 64),
                IsActive = rule.IsActive ? 1u : 0u,
                PortRanges = new PortRange[32],
                IpAddresses = new IpAddressEntry[64]
            };

            for (int i = 0; i < nativeRule.PortRangeCount; i++)
            {
                nativeRule.PortRanges[i] = rule.PortRanges[i];
            }

            // Copy IP addresses
            for (int i = 0; i < nativeRule.IpAddressCount; i++)
            {
                nativeRule.IpAddresses[i] = rule.IpAddresses[i];
            }
            // Zero out unused entries
            for (int i = (int)nativeRule.IpAddressCount; i < 64; i++)
            {
                nativeRule.IpAddresses[i] = new IpAddressEntry { AddressFamily = 0 };
            }

            var request = new NativeAddRuleRequest { Rule = nativeRule };
            var inputSize = Marshal.SizeOf<NativeAddRuleRequest>();
            var inputPtr = IntPtr.Zero;
            var outputPtr = IntPtr.Zero;

            try
            {
                inputPtr = Marshal.AllocHGlobal(inputSize);
                outputPtr = Marshal.AllocHGlobal(sizeof(uint));

                // Zero out memory first to ensure clean state
                for (int i = 0; i < inputSize; i++)
                {
                    Marshal.WriteByte(inputPtr, i, 0);
                }

                Marshal.StructureToPtr(request, inputPtr, false);

                if (DeviceIoControl(_deviceHandle!, IOCTL_FIREWALL_ADD_RULE,
                    inputPtr, (uint)inputSize, outputPtr, sizeof(uint), out _, IntPtr.Zero))
                {
                    // Read the RuleId returned by the driver
                    rule.RuleId = (uint)Marshal.ReadInt32(outputPtr);
                    return true;
                }
                return false;
            }
            catch (Exception)
            {
                return false;
            }
            finally
            {
                if (inputPtr != IntPtr.Zero)
                    Marshal.FreeHGlobal(inputPtr);
                if (outputPtr != IntPtr.Zero)
                    Marshal.FreeHGlobal(outputPtr);
            }
        }

        public bool RemoveRule(uint ruleId)
        {
            if (!IsConnected) return false;

            var request = new NativeRemoveRuleRequest { RuleId = ruleId };
            var inputSize = Marshal.SizeOf<NativeRemoveRuleRequest>();
            var inputPtr = Marshal.AllocHGlobal(inputSize);

            try
            {
                Marshal.StructureToPtr(request, inputPtr, false);
                return DeviceIoControl(_deviceHandle!, IOCTL_FIREWALL_REMOVE_RULE,
                    inputPtr, (uint)inputSize, IntPtr.Zero, 0, out _, IntPtr.Zero);
            }
            finally
            {
                Marshal.FreeHGlobal(inputPtr);
            }
        }

        public bool ClearRules()
        {
            if (!IsConnected) return false;
            return DeviceIoControl(_deviceHandle!, IOCTL_FIREWALL_CLEAR_RULES,
                IntPtr.Zero, 0, IntPtr.Zero, 0, out _, IntPtr.Zero);
        }

        public bool SetMonitoring(bool enabled)
        {
            if (!IsConnected) return false;

            var request = new NativeSetMonitorRequest { EnableMonitoring = enabled ? 1u : 0u };
            var inputSize = Marshal.SizeOf<NativeSetMonitorRequest>();
            var inputPtr = Marshal.AllocHGlobal(inputSize);

            try
            {
                Marshal.StructureToPtr(request, inputPtr, false);
                return DeviceIoControl(_deviceHandle!, IOCTL_FIREWALL_SET_MONITOR,
                    inputPtr, (uint)inputSize, IntPtr.Zero, 0, out _, IntPtr.Zero);
            }
            finally
            {
                Marshal.FreeHGlobal(inputPtr);
            }
        }

        public Guid? GetEtwProviderGuid()
        {
            if (!IsConnected) return null;

            var outputSize = Marshal.SizeOf<Guid>();
            var outputPtr = Marshal.AllocHGlobal(outputSize);

            try
            {
                if (DeviceIoControl(_deviceHandle!, IOCTL_FIREWALL_GET_ETW_GUID,
                    IntPtr.Zero, 0, outputPtr, (uint)outputSize, out _, IntPtr.Zero))
                {
                    return Marshal.PtrToStructure<Guid>(outputPtr);
                }
            }
            finally
            {
                Marshal.FreeHGlobal(outputPtr);
            }

            return null;
        }

        public void Dispose()
        {
            if (!_disposed)
            {
                _deviceHandle?.Dispose();
                _disposed = true;
            }
            GC.SuppressFinalize(this);
        }

        // Native structures for marshalling
        [StructLayout(LayoutKind.Sequential)]
        private struct NativeFirewallStatus
        {
            [MarshalAs(UnmanagedType.U4)]
            public uint IsEnabled;
            public uint RuleCount;
            public uint BlockedAppCount;
            public uint PacketsBlocked;
            public uint PacketsAllowed;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 8, CharSet = CharSet.Unicode)]
        private struct NativeBlockAppRequest
        {
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 520)]
            public string ApplicationPath;
            public uint ProcessId;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 8, CharSet = CharSet.Unicode)]
        private struct NativeFirewallRule
        {
            public uint RuleId;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 520)]
            public string ApplicationPath;
            public uint ProcessId;  // 0 = match by path, non-zero = match by PID
            public uint Action;
            public uint Direction;  // Traffic direction (0=Any, 1=Input, 2=Output)
            public uint PortRangeCount;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
            public PortRange[] PortRanges;
            public uint IpAddressCount;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 64)]
            public IpAddressEntry[] IpAddresses;
            public uint IsActive;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct NativeAddRuleRequest
        {
            public NativeFirewallRule Rule;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct NativeRemoveRuleRequest
        {
            public uint RuleId;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct NativeSetMonitorRequest
        {
            [MarshalAs(UnmanagedType.U4)]
            public uint EnableMonitoring;
        }
    }
}
