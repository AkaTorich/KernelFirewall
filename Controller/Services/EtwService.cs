using System;
using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using System.Threading;
using FirewallController.Models;

namespace FirewallController.Services
{
    /// <summary>
    /// ETW Consumer service for real-time network event tracing from kernel driver
    /// </summary>
    public class EtwService : IDisposable
    {
        // ETW Provider GUID from driver - {A7B8C9D0-E1F2-3456-7890-ABCDEF123456}
        private static readonly Guid ProviderGuid = new Guid("A7B8C9D0-E1F2-3456-7890-ABCDEF123456");
        
        private const string SessionName = "KernelFirewallSession";
        private const int ETW_EVENT_ID_NETWORK = 1;
        
        private long _sessionHandle;
        private long _traceHandle;
        private Thread? _processingThread;
        private volatile bool _isRunning;
        private bool _disposed;
        
        // prevent GC of callback delegate
        private EventRecordCallback? _callbackDelegate;

        // Event buffer
        private readonly ConcurrentQueue<TrafficEntry> _eventQueue = new();
        private const int MaxQueueSize = 1000;

        // Event callback delegate
        public event Action<TrafficEntry>? OnNetworkEvent;

        #region Native ETW Structures and Functions

        [StructLayout(LayoutKind.Sequential)]
        private struct WNODE_HEADER
        {
            public uint BufferSize;
            public uint ProviderId;
            public ulong HistoricalContext;
            public long TimeStamp;
            public Guid Guid;
            public uint ClientContext;
            public uint Flags;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct EVENT_TRACE_PROPERTIES
        {
            public WNODE_HEADER Wnode;
            public uint BufferSize;
            public uint MinimumBuffers;
            public uint MaximumBuffers;
            public uint MaximumFileSize;
            public uint LogFileMode;
            public uint FlushTimer;
            public uint EnableFlags;
            public int AgeLimit;
            public uint NumberOfBuffers;
            public uint FreeBuffers;
            public uint EventsLost;
            public uint BuffersWritten;
            public uint LogBuffersLost;
            public uint RealTimeBuffersLost;
            public IntPtr LoggerThreadId;
            public uint LogFileNameOffset;
            public uint LoggerNameOffset;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct EVENT_TRACE_LOGFILEW
        {
            [MarshalAs(UnmanagedType.LPWStr)]
            public string LogFileName;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string LoggerName;
            public long CurrentTime;
            public uint BuffersRead;
            public uint LogFileMode;
            public EVENT_TRACE CurrentEvent;
            public TRACE_LOGFILE_HEADER LogfileHeader;
            public IntPtr BufferCallback;
            public uint BufferSize;
            public uint Filled;
            public uint EventsLost;
            public EventRecordCallback EventRecordCallback;
            public uint IsKernelTrace;
            public IntPtr Context;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct EVENT_TRACE
        {
            public EVENT_TRACE_HEADER Header;
            public uint InstanceId;
            public uint ParentInstanceId;
            public Guid ParentGuid;
            public IntPtr MofData;
            public uint MofLength;
            public uint ClientContext;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct EVENT_TRACE_HEADER
        {
            public ushort Size;
            public ushort FieldTypeFlags;
            public byte Type;
            public byte Level;
            public ushort Version;
            public uint ThreadId;
            public uint ProcessId;
            public long TimeStamp;
            public Guid Guid;
            public uint KernelTime;
            public uint UserTime;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct TRACE_LOGFILE_HEADER
        {
            public uint BufferSize;
            public byte MajorVersion;
            public byte MinorVersion;
            public byte SubVersion;
            public byte SubMinorVersion;
            public uint ProviderVersion;
            public uint NumberOfProcessors;
            public long EndTime;
            public uint TimerResolution;
            public uint MaximumFileSize;
            public uint LogFileMode;
            public uint BuffersWritten;
            public Guid LogInstanceGuid;
            public IntPtr LoggerName;
            public IntPtr LogFileName;
            public TIME_ZONE_INFORMATION TimeZone;
            public long BootTime;
            public long PerfFreq;
            public long StartTime;
            public uint ReservedFlags;
            public uint BuffersLost;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct TIME_ZONE_INFORMATION
        {
            public int Bias;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)]
            public string StandardName;
            public SYSTEMTIME StandardDate;
            public int StandardBias;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)]
            public string DaylightName;
            public SYSTEMTIME DaylightDate;
            public int DaylightBias;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SYSTEMTIME
        {
            public ushort Year;
            public ushort Month;
            public ushort DayOfWeek;
            public ushort Day;
            public ushort Hour;
            public ushort Minute;
            public ushort Second;
            public ushort Milliseconds;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct EVENT_RECORD
        {
            public EVENT_HEADER EventHeader;
            public ETW_BUFFER_CONTEXT BufferContext;
            public ushort ExtendedDataCount;
            public ushort UserDataLength;
            public IntPtr ExtendedData;
            public IntPtr UserData;
            public IntPtr UserContext;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct EVENT_HEADER
        {
            public ushort Size;
            public ushort HeaderType;
            public ushort Flags;
            public ushort EventProperty;
            public uint ThreadId;
            public uint ProcessId;
            public long TimeStamp;
            public Guid ProviderId;
            public EVENT_DESCRIPTOR EventDescriptor;
            public long ProcessorTime;
            public Guid ActivityId;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct EVENT_DESCRIPTOR
        {
            public ushort Id;
            public byte Version;
            public byte Channel;
            public byte Level;
            public byte Opcode;
            public ushort Task;
            public ulong Keyword;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct ETW_BUFFER_CONTEXT
        {
            public byte ProcessorNumber;
            public byte Alignment;
            public ushort LoggerId;
        }

        private const int ETW_MAX_PACKET_DATA = 12800;

        // Address family constants (matching driver)
        private const ushort ADDRESS_FAMILY_IPV4 = 2;
        private const ushort ADDRESS_FAMILY_IPV6 = 23;

        // ETW Event header - fixed size part with IPv6 support
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        private unsafe struct EtwEventHeader
        {
            public ulong Timestamp;           // 0-7 (8 bytes)
            public uint ProcessId;            // 8-11 (4 bytes)
            public fixed byte ProcessName[64]; // 12-75 (64 bytes)
            public ushort AddressFamily;      // 76-77 (2 bytes)
            public ushort Reserved1;          // 78-79 (2 bytes)
            // Union: 32 bytes total (80-111)
            public fixed byte AddressUnion[32]; // IPv4 (8 bytes) OR IPv6 (32 bytes)
            public ushort LocalPort;          // 112-113 (2 bytes)
            public ushort RemotePort;         // 114-115 (2 bytes)
            public byte Protocol;             // 116 (1 byte)
            public byte Direction;            // 117 (1 byte)
            public byte WasBlocked;           // 118 (1 byte)
            public byte Reserved2;            // 119 (1 byte)
            public ushort DataSize;           // 120-121 (2 bytes)
            // Total: 122 bytes
        }

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate void EventRecordCallback(ref EVENT_RECORD eventRecord);

        private const uint EVENT_TRACE_REAL_TIME_MODE = 0x00000100;
        private const uint PROCESS_TRACE_MODE_REAL_TIME = 0x00000100;
        private const uint PROCESS_TRACE_MODE_EVENT_RECORD = 0x10000000;
        private const uint WNODE_FLAG_TRACED_GUID = 0x00020000;
        private const uint EVENT_TRACE_CONTROL_STOP = 1;
        private const uint EVENT_CONTROL_CODE_ENABLE_PROVIDER = 1;

        [DllImport("advapi32.dll", EntryPoint = "StartTraceW", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern uint StartTrace(
            out long sessionHandle,
            [MarshalAs(UnmanagedType.LPWStr)] string sessionName,
            IntPtr properties);

        [DllImport("advapi32.dll", EntryPoint = "ControlTraceW", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern uint ControlTrace(
            long sessionHandle,
            [MarshalAs(UnmanagedType.LPWStr)] string? sessionName,
            IntPtr properties,
            uint controlCode);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern uint EnableTraceEx2(
            long sessionHandle,
            ref Guid providerId,
            uint controlCode,
            byte level,
            ulong matchAnyKeyword,
            ulong matchAllKeyword,
            uint timeout,
            IntPtr enableParameters);

        [DllImport("advapi32.dll", EntryPoint = "OpenTraceW", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern long OpenTrace(ref EVENT_TRACE_LOGFILEW logfile);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern uint ProcessTrace(
            [In] long[] handleArray,
            uint handleCount,
            IntPtr startTime,
            IntPtr endTime);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern uint CloseTrace(long traceHandle);

        private const uint ERROR_SUCCESS = 0;
        private const uint ERROR_ALREADY_EXISTS = 183;
        private const long INVALID_PROCESSTRACE_HANDLE = -1;

        #endregion

        public bool IsRunning => _isRunning;

        public bool Start()
        {
            if (_isRunning) return true;

            try
            {
                LogWindow.Log("ETW: Starting...");
                
                // Stop any existing session first
                StopExistingSession();

                // Create new ETW session
                if (!CreateSession())
                {
                    LogWindow.Log("ETW: Failed to create session");
                    return false;
                }

                LogWindow.Log("ETW: Session created");

                // Enable provider
                if (!EnableProvider())
                {
                    LogWindow.Log("ETW: Failed to enable provider");
                    StopSession();
                    return false;
                }

                LogWindow.Log("ETW: Provider enabled");

                // Start processing thread
                _isRunning = true;
                _processingThread = new Thread(ProcessEvents)
                {
                    Name = "ETW Processing",
                    IsBackground = true
                };
                _processingThread.Start();

                LogWindow.Log("ETW: Service started successfully");
                return true;
            }
            catch (Exception ex)
            {
                LogWindow.Log($"ETW: Start failed - {ex.Message}");
                return false;
            }
        }

        public void Stop()
        {
            if (!_isRunning) return;

            _isRunning = false;

            try
            {
                // Close trace handle to unblock ProcessTrace
                if (_traceHandle != 0 && _traceHandle != INVALID_PROCESSTRACE_HANDLE)
                {
                    CloseTrace(_traceHandle);
                    _traceHandle = 0;
                }

                // Wait for processing thread
                _processingThread?.Join(2000);

                StopSession();
            }
            catch (Exception ex)
            {
                LogWindow.Log($"ETW: Stop error - {ex.Message}");
            }
            
            LogWindow.Log("ETW: Service stopped");
        }

        private void StopExistingSession()
        {
            try
            {
                int bufferSize = Marshal.SizeOf<EVENT_TRACE_PROPERTIES>() + (SessionName.Length + 1) * 2 + 256;
                IntPtr buffer = Marshal.AllocHGlobal(bufferSize);

                try
                {
                    RtlZeroMemory(buffer, bufferSize);
                    
                    var props = new EVENT_TRACE_PROPERTIES
                    {
                        Wnode = new WNODE_HEADER
                        {
                            BufferSize = (uint)bufferSize
                        },
                        LoggerNameOffset = (uint)Marshal.SizeOf<EVENT_TRACE_PROPERTIES>()
                    };

                    Marshal.StructureToPtr(props, buffer, false);
                    ControlTrace(0, SessionName, buffer, EVENT_TRACE_CONTROL_STOP);
                }
                finally
                {
                    Marshal.FreeHGlobal(buffer);
                }
            }
            catch { }
        }

        [DllImport("kernel32.dll")]
        private static extern void RtlZeroMemory(IntPtr dst, int length);

        private bool CreateSession()
        {
            int bufferSize = Marshal.SizeOf<EVENT_TRACE_PROPERTIES>() + (SessionName.Length + 1) * 2 + 256;
            IntPtr buffer = Marshal.AllocHGlobal(bufferSize);

            try
            {
                RtlZeroMemory(buffer, bufferSize);
                
                var props = new EVENT_TRACE_PROPERTIES
                {
                    Wnode = new WNODE_HEADER
                    {
                        BufferSize = (uint)bufferSize,
                        Flags = WNODE_FLAG_TRACED_GUID,
                        ClientContext = 1 // QPC
                    },
                    LogFileMode = EVENT_TRACE_REAL_TIME_MODE,
                    LoggerNameOffset = (uint)Marshal.SizeOf<EVENT_TRACE_PROPERTIES>(),
                    BufferSize = 64,
                    MinimumBuffers = 4,
                    MaximumBuffers = 64,
                    FlushTimer = 1
                };

                Marshal.StructureToPtr(props, buffer, false);

                uint result = StartTrace(out _sessionHandle, SessionName, buffer);
                
                if (result != ERROR_SUCCESS && result != ERROR_ALREADY_EXISTS)
                {
                    LogWindow.Log($"ETW: StartTrace error {result}");
                    return false;
                }

                if (result == ERROR_ALREADY_EXISTS)
                {
                    LogWindow.Log("ETW: Session already exists, reusing");
                }

                return true;
            }
            catch (Exception ex)
            {
                LogWindow.Log($"ETW: CreateSession exception - {ex.Message}");
                return false;
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        private bool EnableProvider()
        {
            try
            {
                Guid guid = ProviderGuid;
                uint result = EnableTraceEx2(
                    _sessionHandle,
                    ref guid,
                    EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                    5, // TRACE_LEVEL_VERBOSE
                    0xFFFFFFFFFFFFFFFF,
                    0,
                    0,
                    IntPtr.Zero);

                if (result != ERROR_SUCCESS)
                {
                    LogWindow.Log($"ETW: EnableTraceEx2 error {result}");
                    return false;
                }

                return true;
            }
            catch (Exception ex)
            {
                LogWindow.Log($"ETW: EnableProvider exception - {ex.Message}");
                return false;
            }
        }

        private void ProcessEvents()
        {
            try
            {
                // Keep delegate alive
                _callbackDelegate = EventCallback;
                
                var logfile = new EVENT_TRACE_LOGFILEW
                {
                    LoggerName = SessionName,
                    LogFileMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD,
                    EventRecordCallback = _callbackDelegate
                };

                _traceHandle = OpenTrace(ref logfile);
                if (_traceHandle == INVALID_PROCESSTRACE_HANDLE || _traceHandle == 0)
                {
                    int error = Marshal.GetLastWin32Error();
                    LogWindow.Log($"ETW: OpenTrace failed, error {error}");
                    return;
                }

                LogWindow.Log($"ETW: OpenTrace success, handle={_traceHandle}");

                long[] handles = new long[] { _traceHandle };
                uint result = ProcessTrace(handles, 1, IntPtr.Zero, IntPtr.Zero);
                
                if (result != ERROR_SUCCESS && _isRunning)
                {
                    LogWindow.Log($"ETW: ProcessTrace ended, code {result}");
                }
            }
            catch (Exception ex)
            {
                if (_isRunning)
                {
                    LogWindow.Log($"ETW: ProcessEvents error - {ex.Message}");
                }
            }
        }

        private void EventCallback(ref EVENT_RECORD eventRecord)
        {
            try
            {
                if (eventRecord.EventHeader.ProviderId != ProviderGuid)
                    return;

                if (eventRecord.EventHeader.EventDescriptor.Id != ETW_EVENT_ID_NETWORK)
                    return;

                if (eventRecord.UserData == IntPtr.Zero)
                    return;

                int headerSize = Marshal.SizeOf<EtwEventHeader>();
                if (eventRecord.UserDataLength < headerSize)
                    return;

                // Read header first
                var header = Marshal.PtrToStructure<EtwEventHeader>(eventRecord.UserData);
                
                // Read packet data if available
                byte[] packetData = Array.Empty<byte>();
                if (header.DataSize > 0 && eventRecord.UserDataLength > headerSize)
                {
                    int dataLen = Math.Min(header.DataSize, eventRecord.UserDataLength - headerSize);
                    dataLen = Math.Min(dataLen, ETW_MAX_PACKET_DATA);
                    packetData = new byte[dataLen];
                    Marshal.Copy(IntPtr.Add(eventRecord.UserData, headerSize), packetData, 0, dataLen);
                }

                var entry = ConvertToTrafficEntry(header, packetData);

                // Add to queue
                if (_eventQueue.Count < MaxQueueSize)
                {
                    _eventQueue.Enqueue(entry);
                }

                // Raise event
                OnNetworkEvent?.Invoke(entry);
            }
            catch (Exception ex)
            {
                LogWindow.Log($"ETW: Callback error - {ex.Message}");
            }
        }

        private unsafe TrafficEntry ConvertToTrafficEntry(EtwEventHeader header, byte[] packetData)
        {
            DateTime timestamp;
            try
            {
                timestamp = header.Timestamp > 0
                    ? DateTime.FromFileTimeUtc((long)header.Timestamp).ToLocalTime()
                    : DateTime.Now;
            }
            catch
            {
                timestamp = DateTime.Now;
            }

            // Convert process name from fixed byte array to string
            var processName = "Unknown";
            try
            {
                int length = 0;
                while (length < 64 && header.ProcessName[length] != 0)
                    length++;
                if (length > 0)
                {
                    byte[] nameBytes = new byte[length];
                    for (int i = 0; i < length; i++)
                        nameBytes[i] = header.ProcessName[i];
                    processName = System.Text.Encoding.ASCII.GetString(nameBytes);
                }
            }
            catch
            {
                processName = "Unknown";
            }

            // Extract IP addresses from union
            string localIp, remoteIp;
            if (header.AddressFamily == ADDRESS_FAMILY_IPV4)
            {
                // IPv4: first 4 bytes = LocalIp, next 4 bytes = RemoteIp
                uint localIpV4 = BitConverter.ToUInt32(new byte[] {
                    header.AddressUnion[0], header.AddressUnion[1],
                    header.AddressUnion[2], header.AddressUnion[3]
                }, 0);
                uint remoteIpV4 = BitConverter.ToUInt32(new byte[] {
                    header.AddressUnion[4], header.AddressUnion[5],
                    header.AddressUnion[6], header.AddressUnion[7]
                }, 0);
                localIp = IpV4ToString(localIpV4);
                remoteIp = IpV4ToString(remoteIpV4);
            }
            else if (header.AddressFamily == ADDRESS_FAMILY_IPV6)
            {
                // IPv6: first 16 bytes = LocalIp, next 16 bytes = RemoteIp
                byte[] localIpV6 = new byte[16];
                byte[] remoteIpV6 = new byte[16];
                for (int i = 0; i < 16; i++)
                {
                    localIpV6[i] = header.AddressUnion[i];
                    remoteIpV6[i] = header.AddressUnion[16 + i];
                }
                localIp = IpV6ToString(localIpV6);
                remoteIp = IpV6ToString(remoteIpV6);
            }
            else
            {
                localIp = "0.0.0.0";
                remoteIp = "0.0.0.0";
            }

            // Register process in global registry
            try
            {
                if (header.ProcessId > 0 && !string.IsNullOrWhiteSpace(processName))
                {
                    var processService = new ProcessService();
                    var processPath = processService.GetProcessPath((int)header.ProcessId);
                    if (!string.IsNullOrWhiteSpace(processPath))
                    {
                        ProcessRegistryService.Instance.RegisterProcess(processName, processPath);
                    }
                }
            }
            catch { }

            return new TrafficEntry
            {
                Timestamp = timestamp,
                ProcessId = header.ProcessId,
                ProcessName = processName,
                LocalAddress = $"{localIp}:{header.LocalPort}",
                RemoteAddress = $"{remoteIp}:{header.RemotePort}",
                LocalIpOnly = localIp,
                LocalPortOnly = header.LocalPort,
                RemoteIpOnly = remoteIp,
                RemotePortOnly = header.RemotePort,
                Protocol = (ProtocolType)header.Protocol,
                Direction = (PacketDirection)header.Direction,
                WasBlocked = header.WasBlocked != 0,
                DataSize = header.DataSize,
                PacketData = packetData ?? Array.Empty<byte>()
            };
        }

        private static string IpV4ToString(uint ip)
        {
            return $"{(ip >> 24) & 0xFF}.{(ip >> 16) & 0xFF}.{(ip >> 8) & 0xFF}.{ip & 0xFF}";
        }

        private static string IpV6ToString(byte[] ipV6)
        {
            try
            {
                var addr = new System.Net.IPAddress(ipV6);
                return addr.ToString();
            }
            catch
            {
                return "::";
            }
        }

        private void StopSession()
        {
            if (_sessionHandle == 0) return;

            try
            {
                int bufferSize = Marshal.SizeOf<EVENT_TRACE_PROPERTIES>() + 256;
                IntPtr buffer = Marshal.AllocHGlobal(bufferSize);

                try
                {
                    RtlZeroMemory(buffer, bufferSize);
                    
                    var props = new EVENT_TRACE_PROPERTIES
                    {
                        Wnode = new WNODE_HEADER
                        {
                            BufferSize = (uint)bufferSize
                        },
                        LoggerNameOffset = (uint)Marshal.SizeOf<EVENT_TRACE_PROPERTIES>()
                    };

                    Marshal.StructureToPtr(props, buffer, false);
                    ControlTrace(_sessionHandle, null, buffer, EVENT_TRACE_CONTROL_STOP);
                }
                finally
                {
                    Marshal.FreeHGlobal(buffer);
                }
            }
            catch { }
            
            _sessionHandle = 0;
        }

        public TrafficEntry? DequeueEvent()
        {
            return _eventQueue.TryDequeue(out var entry) ? entry : null;
        }

        public int QueueCount => _eventQueue.Count;

        public void ClearQueue()
        {
            while (_eventQueue.TryDequeue(out _)) { }
        }

        public void Dispose()
        {
            if (_disposed) return;
            Stop();
            _disposed = true;
            GC.SuppressFinalize(this);
        }
    }
}
