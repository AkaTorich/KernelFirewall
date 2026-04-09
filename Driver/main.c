/*
 * KernelFirewall - ETW + WFP Firewall Driver
 * Event Tracing for Windows based network monitoring with WFP filtering
 */

#include <ntddk.h>
#include <wdm.h>

#pragma warning(push)
#pragma warning(disable: 4201)
#include <ndis.h>
#pragma warning(pop)

#include <fwpsk.h>
#include <fwpmk.h>
#include <ntstrsafe.h>
#include <evntrace.h>
#include <initguid.h>

#include "../Common/FirewallCommon.h"

#ifndef min
#define min(a,b) (((a) < (b)) ? (a) : (b))
#endif

// Kernel functions
NTKERNELAPI NTSTATUS PsLookupProcessByProcessId(
    _In_ HANDLE ProcessId,
    _Outptr_ PEPROCESS *Process
);

NTKERNELAPI PCHAR PsGetProcessImageFileName(
    _In_ PEPROCESS Process
);

// Forward declarations for blocking and rule-checking functions
BOOLEAN IsAppBlockedByPid(ULONG ProcessId);
BOOLEAN IsAppBlockedByName(PCHAR ProcessName);
BOOLEAN CheckRuleMatchByPid(ULONG ProcessId, USHORT AddressFamily,
                           ULONG LocalIpV4, PUCHAR LocalIpV6, USHORT LocalPort,
                           ULONG RemoteIpV4, PUCHAR RemoteIpV6, USHORT RemotePort,
                           UCHAR PacketDirection);
BOOLEAN CheckRuleMatchByName(PCHAR ProcessName, USHORT AddressFamily,
                            ULONG LocalIpV4, PUCHAR LocalIpV6, USHORT LocalPort,
                            ULONG RemoteIpV4, PUCHAR RemoteIpV6, USHORT RemotePort,
                            UCHAR PacketDirection);
BOOLEAN CheckWildcardRules(USHORT AddressFamily,
                          ULONG LocalIpV4, PUCHAR LocalIpV6, USHORT LocalPort,
                          ULONG RemoteIpV4, PUCHAR RemoteIpV6, USHORT RemotePort,
                          UCHAR PacketDirection);

// IPv6 support functions
BOOLEAN MatchIPv6Prefix(PUCHAR TestAddr, PUCHAR PrefixAddr, UCHAR PrefixLength);

// ETW Provider GUID - {A7B8C9D0-E1F2-3456-7890-ABCDEF123456}
DEFINE_GUID(ETW_PROVIDER_GUID,
    0xa7b8c9d0, 0xe1f2, 0x3456, 0x78, 0x90, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56);

// ETW globals
REGHANDLE g_EtwRegHandle = 0;
volatile BOOLEAN g_EtwEnabled = FALSE;
volatile UCHAR g_EtwLevel = TRACE_LEVEL_INFORMATION;
volatile ULONGLONG g_EtwKeyword = 0xFFFFFFFFFFFFFFFF;

// Driver globals
PDEVICE_OBJECT g_DeviceObject = NULL;
HANDLE g_EngineHandle = NULL;

// IPv4 callout and filter IDs
UINT32 g_CalloutIdConnect = 0;
UINT32 g_CalloutIdRecv = 0;
UINT32 g_CalloutIdStream = 0;
UINT32 g_CalloutIdDatagram = 0;
UINT64 g_FilterIdConnect = 0;
UINT64 g_FilterIdRecv = 0;
UINT64 g_FilterIdStream = 0;
UINT64 g_FilterIdDatagram = 0;

// IPv6 callout and filter IDs
UINT32 g_CalloutIdConnect_V6 = 0;
UINT32 g_CalloutIdRecv_V6 = 0;
UINT32 g_CalloutIdStream_V6 = 0;
UINT32 g_CalloutIdDatagram_V6 = 0;
UINT64 g_FilterIdConnect_V6 = 0;
UINT64 g_FilterIdRecv_V6 = 0;
UINT64 g_FilterIdStream_V6 = 0;
UINT64 g_FilterIdDatagram_V6 = 0;

volatile BOOLEAN g_IsFilteringEnabled = FALSE;

// Synchronization
KSPIN_LOCK g_RulesLock;
KSPIN_LOCK g_BlockedLock;
KSPIN_LOCK g_CacheLock;

// Rule storage
FIREWALL_RULE g_Rules[MAX_RULES];
volatile ULONG g_RuleCount = 0;
volatile ULONG g_NextRuleId = 1;

// Blocked apps storage
BLOCKED_APP_ENTRY g_BlockedApps[MAX_BLOCKED_APPS];
volatile ULONG g_BlockedAppCount = 0;

// Statistics
volatile LONG64 g_PacketsBlocked = 0;
volatile LONG64 g_PacketsAllowed = 0;
volatile BOOLEAN g_MonitoringEnabled = TRUE;

// Debug log ring buffer
KSPIN_LOCK g_LogLock;
CHAR g_DebugLog[DRIVER_LOG_SIZE];
volatile ULONG g_LogOffset = 0;

static void KfwLog(const char* fmt, ...)
{
    CHAR buf[256];
    va_list args;
    va_start(args, fmt);
    int len = _vsnprintf(buf, sizeof(buf) - 2, fmt, args);
    va_end(args);
    if (len <= 0) return;
    buf[len] = '\n';
    buf[len + 1] = '\0';
    len++;

    DbgPrint("KFW: %s", buf);

    KIRQL irql;
    KeAcquireSpinLock(&g_LogLock, &irql);
    for (int i = 0; i < len && g_LogOffset < DRIVER_LOG_SIZE - 1; i++) {
        g_DebugLog[g_LogOffset++] = buf[i];
    }
    KeReleaseSpinLock(&g_LogLock, irql);
}

// Per-process statistics
KSPIN_LOCK g_StatsLock;
PROCESS_STATS_ENTRY g_ProcessStats[MAX_PROCESS_STATS];
volatile ULONG g_ProcessStatsCount = 0;

// Find or create stats entry for a process (must be called at DISPATCH_LEVEL with g_StatsLock held)
static PPROCESS_STATS_ENTRY FindOrCreateProcessStats(const CHAR* processName)
{
    ULONG i;
    // Search existing
    for (i = 0; i < g_ProcessStatsCount; i++) {
        if (_strnicmp(g_ProcessStats[i].ProcessName, processName, 63) == 0) {
            return &g_ProcessStats[i];
        }
    }
    // Create new if space available
    if (g_ProcessStatsCount < MAX_PROCESS_STATS) {
        PPROCESS_STATS_ENTRY entry = &g_ProcessStats[g_ProcessStatsCount];
        RtlZeroMemory(entry, sizeof(PROCESS_STATS_ENTRY));
        RtlCopyMemory(entry->ProcessName, processName, min(strlen(processName), 63));
        entry->ProcessName[63] = '\0';
        g_ProcessStatsCount++;
        return entry;
    }
    return NULL; // Table full
}

// Connection cache for Stream/Datagram layers
#define MAX_CONN_CACHE 128
typedef struct _CONN_CACHE_ENTRY {
    BOOLEAN InUse;
    USHORT AddressFamily;  // ADDRESS_FAMILY_IPV4 or ADDRESS_FAMILY_IPV6
    UCHAR Direction;       // 0=outbound, 1=inbound
    // Unified address storage
    union {
        // IPv4 addresses
        struct {
            ULONG LocalIp;
            ULONG RemoteIp;
        } V4;
        // IPv6 addresses
        struct {
            UCHAR LocalIp[16];
            UCHAR RemoteIp[16];
        } V6;
    };
    USHORT LocalPort;
    USHORT RemotePort;
    ULONG ProcessId;
    CHAR ProcessName[64];  // Increased from 16 to support long process names
    BOOLEAN ShouldBlock;
    LARGE_INTEGER Timestamp;
} CONN_CACHE_ENTRY;

CONN_CACHE_ENTRY g_ConnCache[MAX_CONN_CACHE];

// WFP GUIDs
static const GUID FIREWALL_SUBLAYER_GUID = 
    { 0x8a3b5c1d, 0x2e4f, 0x6789, { 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89 } };

static const GUID FIREWALL_CALLOUT_GUID_CONNECT = 
    { 0x1a2b3c4d, 0x5e6f, 0x7890, { 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0 } };

static const GUID FIREWALL_FILTER_GUID_CONNECT = 
    { 0x2b3c4d5e, 0x6f70, 0x8901, { 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01 } };

static const GUID FIREWALL_CALLOUT_GUID_RECV = 
    { 0x3c4d5e6f, 0x7081, 0x9012, { 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12 } };

static const GUID FIREWALL_FILTER_GUID_RECV = 
    { 0x4d5e6f70, 0x8192, 0x0123, { 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23 } };

static const GUID FIREWALL_CALLOUT_GUID_STREAM = 
    { 0x5e6f7081, 0x9203, 0x1234, { 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34 } };

static const GUID FIREWALL_FILTER_GUID_STREAM = 
    { 0x6f708192, 0x0314, 0x2345, { 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45 } };

static const GUID FIREWALL_CALLOUT_GUID_DATAGRAM =
    { 0x70819203, 0x1425, 0x3456, { 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56 } };

static const GUID FIREWALL_FILTER_GUID_DATAGRAM =
    { 0x81920314, 0x2536, 0x4567, { 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67 } };

// IPv6 WFP GUIDs
static const GUID FIREWALL_CALLOUT_GUID_CONNECT_V6 =
    { 0x9a0b1c2d, 0x3e4f, 0x5678, { 0x90, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde } };

static const GUID FIREWALL_FILTER_GUID_CONNECT_V6 =
    { 0xa1b2c3d4, 0x4f50, 0x6789, { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef } };

static const GUID FIREWALL_CALLOUT_GUID_RECV_V6 =
    { 0xb2c3d4e5, 0x5061, 0x7890, { 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0 } };

static const GUID FIREWALL_FILTER_GUID_RECV_V6 =
    { 0xc3d4e5f6, 0x6172, 0x8901, { 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01 } };

static const GUID FIREWALL_CALLOUT_GUID_STREAM_V6 =
    { 0xd4e5f607, 0x7283, 0x9012, { 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12 } };

static const GUID FIREWALL_FILTER_GUID_STREAM_V6 =
    { 0xe5f60718, 0x8394, 0x0123, { 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23 } };

static const GUID FIREWALL_CALLOUT_GUID_DATAGRAM_V6 =
    { 0xf6071829, 0x94a5, 0x1234, { 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34 } };

static const GUID FIREWALL_FILTER_GUID_DATAGRAM_V6 =
    { 0x0718293a, 0xa5b6, 0x2345, { 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45 } };

// Forward declarations
DRIVER_UNLOAD DriverUnload;
DRIVER_DISPATCH DriverDispatch;
NTSTATUS RegisterWfpCallouts(void);
void UnregisterWfpCallouts(void);

// Get process name (ANSI)
_IRQL_requires_max_(DISPATCH_LEVEL)
void GetProcessNameA(PEPROCESS Process, PCHAR Buffer, SIZE_T BufferSize)
{
    PCHAR ansiName;
    SIZE_T len;
    
    if (Buffer == NULL || BufferSize == 0) return;
    Buffer[0] = '\0';
    
    if (Process == NULL) return;
    
    ansiName = PsGetProcessImageFileName(Process);
    if (ansiName == NULL || ansiName[0] == '\0') return;
    
    len = 0;
    while (len < BufferSize - 1 && ansiName[len] != '\0') {
        Buffer[len] = ansiName[len];
        len++;
    }
    Buffer[len] = '\0';
}

// Connection cache functions - recalculate block status for all cached connections
_IRQL_requires_max_(DISPATCH_LEVEL)
void RefreshConnCacheBlockStatus(void)
{
    KIRQL oldIrql;
    ULONG i;
    BOOLEAN shouldBlock;

    KeAcquireSpinLock(&g_CacheLock, &oldIrql);

    for (i = 0; i < MAX_CONN_CACHE; i++) {
        if (!g_ConnCache[i].InUse) continue;

        shouldBlock = FALSE;

        // Check if app is blocked by PID
        if (IsAppBlockedByPid(g_ConnCache[i].ProcessId)) {
            shouldBlock = TRUE;
        }
        // Check if app is blocked by name
        else if (IsAppBlockedByName(g_ConnCache[i].ProcessName)) {
            shouldBlock = TRUE;
        }
        // Check rules by PID
        else if (g_ConnCache[i].AddressFamily == ADDRESS_FAMILY_IPV4) {
            if (!CheckRuleMatchByPid(g_ConnCache[i].ProcessId, g_ConnCache[i].AddressFamily,
                                     g_ConnCache[i].V4.LocalIp, NULL, g_ConnCache[i].LocalPort,
                                     g_ConnCache[i].V4.RemoteIp, NULL, g_ConnCache[i].RemotePort, g_ConnCache[i].Direction)) {
                shouldBlock = TRUE;
            }
            else if (!CheckRuleMatchByName(g_ConnCache[i].ProcessName, g_ConnCache[i].AddressFamily,
                                          g_ConnCache[i].V4.LocalIp, NULL, g_ConnCache[i].LocalPort,
                                          g_ConnCache[i].V4.RemoteIp, NULL, g_ConnCache[i].RemotePort, g_ConnCache[i].Direction)) {
                shouldBlock = TRUE;
            }
            else if (!CheckWildcardRules(g_ConnCache[i].AddressFamily,
                                        g_ConnCache[i].V4.LocalIp, NULL, g_ConnCache[i].LocalPort,
                                        g_ConnCache[i].V4.RemoteIp, NULL, g_ConnCache[i].RemotePort, g_ConnCache[i].Direction)) {
                shouldBlock = TRUE;
            }
        }
        else if (g_ConnCache[i].AddressFamily == ADDRESS_FAMILY_IPV6) {
            if (!CheckRuleMatchByPid(g_ConnCache[i].ProcessId, g_ConnCache[i].AddressFamily,
                                     0, g_ConnCache[i].V6.LocalIp, g_ConnCache[i].LocalPort,
                                     0, g_ConnCache[i].V6.RemoteIp, g_ConnCache[i].RemotePort, g_ConnCache[i].Direction)) {
                shouldBlock = TRUE;
            }
            else if (!CheckRuleMatchByName(g_ConnCache[i].ProcessName, g_ConnCache[i].AddressFamily,
                                          0, g_ConnCache[i].V6.LocalIp, g_ConnCache[i].LocalPort,
                                          0, g_ConnCache[i].V6.RemoteIp, g_ConnCache[i].RemotePort, g_ConnCache[i].Direction)) {
                shouldBlock = TRUE;
            }
            else if (!CheckWildcardRules(g_ConnCache[i].AddressFamily,
                                        0, g_ConnCache[i].V6.LocalIp, g_ConnCache[i].LocalPort,
                                        0, g_ConnCache[i].V6.RemoteIp, g_ConnCache[i].RemotePort, g_ConnCache[i].Direction)) {
                shouldBlock = TRUE;
            }
        }

        g_ConnCache[i].ShouldBlock = shouldBlock;
    }

    KeReleaseSpinLock(&g_CacheLock, oldIrql);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void ClearConnCache(void)
{
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_CacheLock, &oldIrql);
    RtlZeroMemory(g_ConnCache, sizeof(g_ConnCache));
    KeReleaseSpinLock(&g_CacheLock, oldIrql);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
// Unified connection cache function supporting both IPv4 and IPv6
void AddToConnCacheUnified(USHORT AddressFamily,
                          ULONG LocalIpV4, PUCHAR LocalIpV6, USHORT LocalPort,
                          ULONG RemoteIpV4, PUCHAR RemoteIpV6, USHORT RemotePort,
                          ULONG ProcessId, PCHAR ProcessName, BOOLEAN ShouldBlock, UCHAR Direction)
{
    KIRQL oldIrql;
    LARGE_INTEGER now;
    ULONG oldestIdx = 0;
    LARGE_INTEGER oldestTime;
    ULONG i;

    KeQuerySystemTime(&now);
    oldestTime.QuadPart = MAXLONGLONG;

    KeAcquireSpinLock(&g_CacheLock, &oldIrql);

    // Find empty slot or oldest entry (LRU eviction)
    for (i = 0; i < MAX_CONN_CACHE; i++) {
        if (!g_ConnCache[i].InUse) {
            oldestIdx = i;
            break;
        }
        if (g_ConnCache[i].Timestamp.QuadPart < oldestTime.QuadPart) {
            oldestTime = g_ConnCache[i].Timestamp;
            oldestIdx = i;
        }
    }

    // Fill cache entry
    g_ConnCache[oldestIdx].InUse = TRUE;
    g_ConnCache[oldestIdx].AddressFamily = AddressFamily;
    g_ConnCache[oldestIdx].Direction = Direction;
    g_ConnCache[oldestIdx].LocalPort = LocalPort;
    g_ConnCache[oldestIdx].RemotePort = RemotePort;
    g_ConnCache[oldestIdx].ProcessId = ProcessId;
    g_ConnCache[oldestIdx].ShouldBlock = ShouldBlock;
    g_ConnCache[oldestIdx].Timestamp = now;

    // Copy addresses based on family
    if (AddressFamily == ADDRESS_FAMILY_IPV4) {
        g_ConnCache[oldestIdx].V4.LocalIp = LocalIpV4;
        g_ConnCache[oldestIdx].V4.RemoteIp = RemoteIpV4;
    } else if (AddressFamily == ADDRESS_FAMILY_IPV6 && LocalIpV6 != NULL && RemoteIpV6 != NULL) {
        RtlCopyMemory(g_ConnCache[oldestIdx].V6.LocalIp, LocalIpV6, 16);
        RtlCopyMemory(g_ConnCache[oldestIdx].V6.RemoteIp, RemoteIpV6, 16);
    }

    // Copy process name
    if (ProcessName != NULL) {
        for (i = 0; i < 63 && ProcessName[i] != '\0'; i++) {
            g_ConnCache[oldestIdx].ProcessName[i] = ProcessName[i];
        }
        g_ConnCache[oldestIdx].ProcessName[i] = '\0';
    } else {
        g_ConnCache[oldestIdx].ProcessName[0] = '\0';
    }

    KeReleaseSpinLock(&g_CacheLock, oldIrql);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
// Unified cache lookup supporting both IPv4 and IPv6
BOOLEAN LookupConnCacheUnified(USHORT AddressFamily,
                              ULONG LocalIpV4, PUCHAR LocalIpV6, USHORT LocalPort,
                              ULONG RemoteIpV4, PUCHAR RemoteIpV6, USHORT RemotePort,
                              PULONG ProcessId, PCHAR ProcessName, PBOOLEAN ShouldBlock)
{
    KIRQL oldIrql;
    BOOLEAN found = FALSE;
    ULONG i, j;
    BOOLEAN addressMatch;

    KeAcquireSpinLock(&g_CacheLock, &oldIrql);

    for (i = 0; i < MAX_CONN_CACHE; i++) {
        if (!g_ConnCache[i].InUse) continue;
        if (g_ConnCache[i].AddressFamily != AddressFamily) continue;
        if (g_ConnCache[i].LocalPort != LocalPort) continue;
        if (g_ConnCache[i].RemotePort != RemotePort) continue;

        // Check address match based on family
        addressMatch = FALSE;
        if (AddressFamily == ADDRESS_FAMILY_IPV4) {
            // IPv4 comparison
            if (g_ConnCache[i].V4.LocalIp == LocalIpV4 &&
                g_ConnCache[i].V4.RemoteIp == RemoteIpV4) {
                addressMatch = TRUE;
            }
        } else if (AddressFamily == ADDRESS_FAMILY_IPV6 && LocalIpV6 != NULL && RemoteIpV6 != NULL) {
            // IPv6 comparison (compare 16 bytes)
            if (RtlCompareMemory(g_ConnCache[i].V6.LocalIp, LocalIpV6, 16) == 16 &&
                RtlCompareMemory(g_ConnCache[i].V6.RemoteIp, RemoteIpV6, 16) == 16) {
                addressMatch = TRUE;
            }
        }

        if (addressMatch) {
            // Found match - copy data to output parameters
            if (ProcessId) *ProcessId = g_ConnCache[i].ProcessId;
            if (ShouldBlock) *ShouldBlock = g_ConnCache[i].ShouldBlock;
            if (ProcessName) {
                for (j = 0; j < 63 && g_ConnCache[i].ProcessName[j] != '\0'; j++) {
                    ProcessName[j] = g_ConnCache[i].ProcessName[j];
                }
                ProcessName[j] = '\0';
            }
            found = TRUE;
            break;
        }
    }

    KeReleaseSpinLock(&g_CacheLock, oldIrql);
    return found;
}

// ETW callback
VOID NTAPI EtwEnableCallback(
    _In_ LPCGUID SourceId,
    _In_ ULONG IsEnabled,
    _In_ UCHAR Level,
    _In_ ULONGLONG MatchAnyKeyword,
    _In_ ULONGLONG MatchAllKeyword,
    _In_opt_ PEVENT_FILTER_DESCRIPTOR FilterData,
    _Inout_opt_ PVOID CallbackContext)
{
    UNREFERENCED_PARAMETER(SourceId);
    UNREFERENCED_PARAMETER(MatchAllKeyword);
    UNREFERENCED_PARAMETER(FilterData);
    UNREFERENCED_PARAMETER(CallbackContext);

    if (IsEnabled) {
        g_EtwLevel = Level;
        g_EtwKeyword = MatchAnyKeyword;
        g_EtwEnabled = TRUE;
    } else {
        g_EtwEnabled = FALSE;
    }
}

NTSTATUS InitializeEtw(void)
{
    return EtwRegister(&ETW_PROVIDER_GUID, EtwEnableCallback, NULL, &g_EtwRegHandle);
}

void CleanupEtw(void)
{
    if (g_EtwRegHandle != 0) {
        EtwUnregister(g_EtwRegHandle);
        g_EtwRegHandle = 0;
    }
}

// Use ETW_EVENT_HEADER and ETW_MAX_PACKET_DATA from FirewallCommon.h

// Full event allocated from pool
typedef struct _ETW_EVENT_DATA {
    ETW_EVENT_HEADER Header;
    UCHAR PacketData[ETW_MAX_PACKET_DATA];
} ETW_EVENT_DATA, *PETW_EVENT_DATA;

// Log via ETW with packet data - allocates from pool for large data
_IRQL_requires_max_(DISPATCH_LEVEL)
void LogNetworkEventEtw(
    ULONG ProcessId,
    PCHAR ProcessName,
    USHORT AddressFamily,
    ULONG LocalIpV4,
    PUCHAR LocalIpV6,
    USHORT LocalPort,
    ULONG RemoteIpV4,
    PUCHAR RemoteIpV6,
    USHORT RemotePort,
    UCHAR Protocol,
    UCHAR Direction,
    BOOLEAN WasBlocked,
    PVOID PacketData,
    USHORT PacketLen)
{
    PETW_EVENT_DATA eventData;
    LARGE_INTEGER timestamp;
    EVENT_DESCRIPTOR eventDescriptor;
    EVENT_DATA_DESCRIPTOR dataDescriptor;
    SIZE_T i;
    USHORT copyLen;
    ULONG eventSize;

    if (!g_EtwEnabled || !g_MonitoringEnabled || g_EtwRegHandle == 0) {
        return;
    }

    // Calculate actual size needed
    copyLen = 0;
    if (PacketData != NULL && PacketLen > 0) {
        copyLen = (PacketLen > ETW_MAX_PACKET_DATA) ? ETW_MAX_PACKET_DATA : PacketLen;
    }
    eventSize = sizeof(ETW_EVENT_HEADER) + copyLen;

    // Allocate from non-paged pool
    eventData = (PETW_EVENT_DATA)ExAllocatePool2(POOL_FLAG_NON_PAGED, eventSize, 'wfTE');
    if (eventData == NULL) {
        return;
    }

    RtlZeroMemory(eventData, eventSize);
    KeQuerySystemTime(&timestamp);

    eventData->Header.Timestamp = timestamp.QuadPart;
    eventData->Header.ProcessId = ProcessId;

    if (ProcessName != NULL) {
        for (i = 0; i < 63 && ProcessName[i] != '\0'; i++) {
            eventData->Header.ProcessName[i] = ProcessName[i];
        }
        eventData->Header.ProcessName[i] = '\0';
    }

    // Set address family
    eventData->Header.AddressFamily = AddressFamily;

    // Fill address union based on address family
    if (AddressFamily == ADDRESS_FAMILY_IPV4) {
        eventData->Header.V4.LocalIp = LocalIpV4;
        eventData->Header.V4.RemoteIp = RemoteIpV4;
    } else if (AddressFamily == ADDRESS_FAMILY_IPV6 && LocalIpV6 != NULL && RemoteIpV6 != NULL) {
        RtlCopyMemory(eventData->Header.V6.LocalIp, LocalIpV6, 16);
        RtlCopyMemory(eventData->Header.V6.RemoteIp, RemoteIpV6, 16);
    }

    eventData->Header.LocalPort = LocalPort;
    eventData->Header.RemotePort = RemotePort;
    eventData->Header.Protocol = Protocol;
    eventData->Header.Direction = Direction;
    eventData->Header.WasBlocked = WasBlocked ? 1 : 0;
    eventData->Header.DataSize = copyLen;

    // Copy packet data
    if (copyLen > 0) {
        RtlCopyMemory(eventData->PacketData, PacketData, copyLen);
    }

    EventDescCreate(&eventDescriptor,
        ETW_EVENT_ID_NETWORK,
        0, 0,
        TRACE_LEVEL_INFORMATION,
        0, 0,
        ETW_KEYWORD_NETWORK);

    EventDataDescCreate(&dataDescriptor, eventData, eventSize);
    EtwWrite(g_EtwRegHandle, &eventDescriptor, NULL, 1, &dataDescriptor);

    ExFreePoolWithTag(eventData, 'wfTE');
}

// Check if app blocked
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN IsAppBlockedByName(PCHAR ProcessName)
{
    KIRQL oldIrql;
    BOOLEAN isBlocked = FALSE;
    ULONG i;
    SIZE_T j, nameLen, k;
    PWCHAR blockedName;
    CHAR blockedNameA[64];
    
    if (ProcessName == NULL || ProcessName[0] == '\0') {
        return FALSE;
    }

    KeAcquireSpinLock(&g_BlockedLock, &oldIrql);

    for (i = 0; i < g_BlockedAppCount; i++) {
        if (g_BlockedApps[i].IsBlocked) {
            blockedName = g_BlockedApps[i].ApplicationPath;

            // Skip PID-based entries (they are checked by IsAppBlockedByPid)
            if (blockedName[0] == L'P' && blockedName[1] == L'I' &&
                blockedName[2] == L'D' && blockedName[3] == L':') {
                continue;
            }

            PWCHAR p = blockedName;
            while (*p) {
                if (*p == L'\\') blockedName = p + 1;
                p++;
            }

            for (j = 0; j < 63 && blockedName[j] != L'\0'; j++) {
                blockedNameA[j] = (CHAR)blockedName[j];
            }
            blockedNameA[j] = '\0';

            nameLen = 0;
            while (ProcessName[nameLen]) nameLen++;

            if (j == nameLen) {
                BOOLEAN match = TRUE;
                for (k = 0; k < nameLen; k++) {
                    CHAR c1 = ProcessName[k];
                    CHAR c2 = blockedNameA[k];
                    if (c1 >= 'A' && c1 <= 'Z') c1 += 32;
                    if (c2 >= 'A' && c2 <= 'Z') c2 += 32;
                    if (c1 != c2) { match = FALSE; break; }
                }
                if (match) { isBlocked = TRUE; break; }
            }
        }
    }

    KeReleaseSpinLock(&g_BlockedLock, oldIrql);
    return isBlocked;
}

// Check if app blocked by PID (also checks if PID was saved but path matches)
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN IsAppBlockedByPid(ULONG ProcessId)
{
    KIRQL oldIrql;
    BOOLEAN isBlocked = FALSE;
    ULONG i;

    if (ProcessId == 0) {
        return FALSE;
    }

    KeAcquireSpinLock(&g_BlockedLock, &oldIrql);

    for (i = 0; i < g_BlockedAppCount; i++) {
        if (!g_BlockedApps[i].IsBlocked) continue;

        // Match by PID if it was saved (non-zero)
        if (g_BlockedApps[i].ProcessId != 0 && g_BlockedApps[i].ProcessId == ProcessId) {
            isBlocked = TRUE;
            break;
        }

        // If entry has no PID but has path, it will be checked by IsAppBlockedByName
    }

    KeReleaseSpinLock(&g_BlockedLock, oldIrql);
    return isBlocked;
}

// Check wildcard rules (no process specified - applies to ALL processes)
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN CheckWildcardRules(USHORT AddressFamily,
                          ULONG LocalIpV4, PUCHAR LocalIpV6, USHORT LocalPort,
                          ULONG RemoteIpV4, PUCHAR RemoteIpV6, USHORT RemotePort,
                          UCHAR PacketDirection)
{
    KIRQL oldIrql;
    BOOLEAN allowed = TRUE;
    ULONG i, j;
    ULONG targetIpV4;
    PUCHAR targetIpV6;
    USHORT targetPort;

    UNREFERENCED_PARAMETER(LocalIpV4);
    UNREFERENCED_PARAMETER(LocalIpV6);

    KeAcquireSpinLock(&g_RulesLock, &oldIrql);

    for (i = 0; i < g_RuleCount; i++) {
        if (!g_Rules[i].IsActive) continue;
        if (g_Rules[i].ProcessId != 0) continue;  // Not a wildcard rule
        if (g_Rules[i].ApplicationPath[0] != L'\0' && g_Rules[i].ApplicationPath[0] != L'*') continue;  // Not a wildcard rule

        // Check if rule direction matches packet direction
        if (g_Rules[i].Direction == TrafficDirectionInput && PacketDirection != 1) {
            continue;  // Rule is for Input but packet is Output
        }
        if (g_Rules[i].Direction == TrafficDirectionOutput && PacketDirection != 0) {
            continue;  // Rule is for Output but packet is Input
        }

        // Determine which IP/port to check based on traffic direction
        if (g_Rules[i].Direction == TrafficDirectionInput) {
            // Input: IP = remote (from), Port = local (to)
            targetIpV4 = RemoteIpV4;
            targetIpV6 = RemoteIpV6;
            targetPort = LocalPort;
        } else if (g_Rules[i].Direction == TrafficDirectionOutput) {
            // Output: IP = remote (to), Port = remote (to)
            targetIpV4 = RemoteIpV4;
            targetIpV6 = RemoteIpV6;
            targetPort = RemotePort;
        } else {
            // TrafficDirectionAny - use remote (default)
            targetIpV4 = RemoteIpV4;
            targetIpV6 = RemoteIpV6;
            targetPort = RemotePort;
        }

        // This is a wildcard rule - check port/IP filters
        BOOLEAN portOk = (g_Rules[i].PortRangeCount == 0);
        BOOLEAN ipOk = (g_Rules[i].IpAddressCount == 0);

        // Check port ranges
        for (j = 0; j < g_Rules[i].PortRangeCount; j++) {
            if (targetPort >= g_Rules[i].PortRanges[j].StartPort &&
                targetPort <= g_Rules[i].PortRanges[j].EndPort) {
                portOk = TRUE;
                break;
            }
        }

        // Check IP addresses (supports both IPv4 and IPv6)
        for (j = 0; j < g_Rules[i].IpAddressCount; j++) {
            // Skip if address family doesn't match
            if (g_Rules[i].IpAddresses[j].AddressFamily != AddressFamily)
                continue;

            if (AddressFamily == ADDRESS_FAMILY_IPV4) {
                ULONG maskedTarget = targetIpV4 & g_Rules[i].IpAddresses[j].V4.Mask;
                ULONG maskedRule = g_Rules[i].IpAddresses[j].V4.Address & g_Rules[i].IpAddresses[j].V4.Mask;
                if (maskedTarget == maskedRule) {
                    ipOk = TRUE;
                    break;
                }
            } else if (AddressFamily == ADDRESS_FAMILY_IPV6 && targetIpV6 != NULL) {
                if (MatchIPv6Prefix(targetIpV6, g_Rules[i].IpAddresses[j].V6.Address,
                                   g_Rules[i].IpAddresses[j].V6.PrefixLength)) {
                    ipOk = TRUE;
                    break;
                }
            }
        }

        // Apply action based on filters
        switch (g_Rules[i].Action) {
            case FirewallActionBlock:
                if (portOk && ipOk) {
                    allowed = FALSE;
                }
                break;
            case FirewallActionAllow:
                allowed = TRUE;
                break;
            case FirewallActionAllowRestricted:
                allowed = portOk && ipOk;
                break;
        }

        if (!allowed) break;  // First blocking rule wins
    }

    KeReleaseSpinLock(&g_RulesLock, oldIrql);
    return allowed;
}

// IPv6 prefix matching function
// Compares TestAddr with PrefixAddr using the specified prefix length (0-128)
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN MatchIPv6Prefix(PUCHAR TestAddr, PUCHAR PrefixAddr, UCHAR PrefixLength)
{
    UCHAR fullBytes;
    UCHAR remainingBits;
    UCHAR i;
    UCHAR mask;

    // Validate inputs
    if (TestAddr == NULL || PrefixAddr == NULL || PrefixLength > 128) {
        return FALSE;
    }

    // Prefix length of 0 matches everything
    if (PrefixLength == 0) {
        return TRUE;
    }

    // Calculate how many full bytes to compare
    fullBytes = PrefixLength / 8;
    remainingBits = PrefixLength % 8;

    // Compare full bytes
    for (i = 0; i < fullBytes; i++) {
        if (TestAddr[i] != PrefixAddr[i]) {
            return FALSE;
        }
    }

    // Compare remaining bits in the partial byte
    if (remainingBits > 0) {
        // Create mask for the remaining bits
        // For example, if remainingBits = 5, mask = 11111000 (0xF8)
        mask = (UCHAR)(0xFF << (8 - remainingBits));

        if ((TestAddr[fullBytes] & mask) != (PrefixAddr[fullBytes] & mask)) {
            return FALSE;
        }
    }

    return TRUE;
}

// Check rule match by PID
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN CheckRuleMatchByPid(ULONG ProcessId, USHORT AddressFamily,
                           ULONG LocalIpV4, PUCHAR LocalIpV6, USHORT LocalPort,
                           ULONG RemoteIpV4, PUCHAR RemoteIpV6, USHORT RemotePort,
                           UCHAR PacketDirection)
{
    KIRQL oldIrql;
    BOOLEAN allowed = TRUE;
    ULONG i, j;
    ULONG targetIpV4;
    PUCHAR targetIpV6;
    USHORT targetPort;

    UNREFERENCED_PARAMETER(LocalIpV4);
    UNREFERENCED_PARAMETER(LocalIpV6);

    if (ProcessId == 0) {
        return TRUE;
    }

    KeAcquireSpinLock(&g_RulesLock, &oldIrql);

    for (i = 0; i < g_RuleCount; i++) {
        if (!g_Rules[i].IsActive) continue;
        if (g_Rules[i].ProcessId == 0) continue;  // This rule is for name matching
        if (g_Rules[i].ProcessId != ProcessId) continue;  // PID doesn't match

        // Check if rule direction matches packet direction
        if (g_Rules[i].Direction == TrafficDirectionInput && PacketDirection != 1) {
            continue;  // Rule is for Input but packet is Output
        }
        if (g_Rules[i].Direction == TrafficDirectionOutput && PacketDirection != 0) {
            continue;  // Rule is for Output but packet is Input
        }

        // Determine which IP/port to check based on traffic direction
        if (g_Rules[i].Direction == TrafficDirectionInput) {
            // Input: IP = remote (from), Port = local (to)
            targetIpV4 = RemoteIpV4;
            targetIpV6 = RemoteIpV6;
            targetPort = LocalPort;
        } else if (g_Rules[i].Direction == TrafficDirectionOutput) {
            // Output: IP = remote (to), Port = remote (to)
            targetIpV4 = RemoteIpV4;
            targetIpV6 = RemoteIpV6;
            targetPort = RemotePort;
        } else {
            // TrafficDirectionAny - use remote (default)
            targetIpV4 = RemoteIpV4;
            targetIpV6 = RemoteIpV6;
            targetPort = RemotePort;
        }

        // PID matched - now check port/IP filters
        BOOLEAN portOk = (g_Rules[i].PortRangeCount == 0);
        BOOLEAN ipOk = (g_Rules[i].IpAddressCount == 0);

        // Check port ranges
        for (j = 0; j < g_Rules[i].PortRangeCount; j++) {
            if (targetPort >= g_Rules[i].PortRanges[j].StartPort &&
                targetPort <= g_Rules[i].PortRanges[j].EndPort) {
                portOk = TRUE;
                break;
            }
        }

        // Check IP addresses (supports both IPv4 and IPv6)
        for (j = 0; j < g_Rules[i].IpAddressCount; j++) {
            // Skip if address family doesn't match
            if (g_Rules[i].IpAddresses[j].AddressFamily != AddressFamily)
                continue;

            if (AddressFamily == ADDRESS_FAMILY_IPV4) {
                ULONG maskedTarget = targetIpV4 & g_Rules[i].IpAddresses[j].V4.Mask;
                ULONG maskedRule = g_Rules[i].IpAddresses[j].V4.Address & g_Rules[i].IpAddresses[j].V4.Mask;
                if (maskedTarget == maskedRule) {
                    ipOk = TRUE;
                    break;
                }
            } else if (AddressFamily == ADDRESS_FAMILY_IPV6 && targetIpV6 != NULL) {
                if (MatchIPv6Prefix(targetIpV6, g_Rules[i].IpAddresses[j].V6.Address,
                                   g_Rules[i].IpAddresses[j].V6.PrefixLength)) {
                    ipOk = TRUE;
                    break;
                }
            }
        }

        // Apply action based on filters
        switch (g_Rules[i].Action) {
            case FirewallActionBlock:
                // If no filters specified -> block ALL traffic
                // If filters specified -> block only matching ports/IPs
                if (portOk && ipOk) {
                    allowed = FALSE;
                }
                break;
            case FirewallActionAllow:
                allowed = TRUE;
                break;
            case FirewallActionAllowRestricted:
                allowed = portOk && ipOk;  // Only allow if ports AND IP match
                break;
        }
        break;
    }

    KeReleaseSpinLock(&g_RulesLock, oldIrql);
    return allowed;
}

// Check rule match - supports both PID and name matching, with port/IP filtering
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN CheckRuleMatchByName(PCHAR ProcessName, USHORT AddressFamily,
                            ULONG LocalIpV4, PUCHAR LocalIpV6, USHORT LocalPort,
                            ULONG RemoteIpV4, PUCHAR RemoteIpV6, USHORT RemotePort,
                            UCHAR PacketDirection)
{
    KIRQL oldIrql;
    BOOLEAN allowed = TRUE;
    ULONG i, j;
    SIZE_T nameLen, k;
    PWCHAR ruleName;
    CHAR ruleNameA[64];
    ULONG targetIpV4;
    PUCHAR targetIpV6;
    USHORT targetPort;

    UNREFERENCED_PARAMETER(LocalIpV4);
    UNREFERENCED_PARAMETER(LocalIpV6);

    if (ProcessName == NULL || ProcessName[0] == '\0') {
        return TRUE;
    }

    KeAcquireSpinLock(&g_RulesLock, &oldIrql);

    for (i = 0; i < g_RuleCount; i++) {
        if (!g_Rules[i].IsActive) continue;
        if (g_Rules[i].ProcessId != 0) continue;  // This rule is for PID matching

        BOOLEAN processMatch = FALSE;

        // Check if rule matches by process name
        ruleName = g_Rules[i].ApplicationPath;
        PWCHAR p = ruleName;
        while (*p) {
            if (*p == L'\\') ruleName = p + 1;
            p++;
        }

        for (j = 0; j < 63 && ruleName[j] != L'\0'; j++) {
            ruleNameA[j] = (CHAR)ruleName[j];
        }
        ruleNameA[j] = '\0';

        nameLen = 0;
        while (ProcessName[nameLen]) nameLen++;

        if (j == nameLen) {
            BOOLEAN match = TRUE;
            for (k = 0; k < nameLen; k++) {
                CHAR c1 = ProcessName[k];
                CHAR c2 = ruleNameA[k];
                if (c1 >= 'A' && c1 <= 'Z') c1 += 32;
                if (c2 >= 'A' && c2 <= 'Z') c2 += 32;
                if (c1 != c2) { match = FALSE; break; }
            }
            if (match) processMatch = TRUE;
        }

        if (processMatch) {
            // Check if rule direction matches packet direction
            if (g_Rules[i].Direction == TrafficDirectionInput && PacketDirection != 1) {
                continue;  // Rule is for Input but packet is Output
            }
            if (g_Rules[i].Direction == TrafficDirectionOutput && PacketDirection != 0) {
                continue;  // Rule is for Output but packet is Input
            }

            // Determine which IP/port to check based on traffic direction
            if (g_Rules[i].Direction == TrafficDirectionInput) {
                // Input: IP = remote (from), Port = local (to)
                targetIpV4 = RemoteIpV4;
                targetIpV6 = RemoteIpV6;
                targetPort = LocalPort;
            } else if (g_Rules[i].Direction == TrafficDirectionOutput) {
                // Output: IP = remote (to), Port = remote (to)
                targetIpV4 = RemoteIpV4;
                targetIpV6 = RemoteIpV6;
                targetPort = RemotePort;
            } else {
                // TrafficDirectionAny - use remote (default)
                targetIpV4 = RemoteIpV4;
                targetIpV6 = RemoteIpV6;
                targetPort = RemotePort;
            }

            // Process matched - now check port/IP filters
            BOOLEAN portOk = (g_Rules[i].PortRangeCount == 0);
            BOOLEAN ipOk = (g_Rules[i].IpAddressCount == 0);

            // Check port ranges
            for (j = 0; j < g_Rules[i].PortRangeCount; j++) {
                if (targetPort >= g_Rules[i].PortRanges[j].StartPort &&
                    targetPort <= g_Rules[i].PortRanges[j].EndPort) {
                    portOk = TRUE;
                    break;
                }
            }

            // Check IP addresses (supports both IPv4 and IPv6)
            for (j = 0; j < g_Rules[i].IpAddressCount; j++) {
                // Skip if address family doesn't match
                if (g_Rules[i].IpAddresses[j].AddressFamily != AddressFamily)
                    continue;

                if (AddressFamily == ADDRESS_FAMILY_IPV4) {
                    ULONG maskedTarget = targetIpV4 & g_Rules[i].IpAddresses[j].V4.Mask;
                    ULONG maskedRule = g_Rules[i].IpAddresses[j].V4.Address & g_Rules[i].IpAddresses[j].V4.Mask;
                    if (maskedTarget == maskedRule) {
                        ipOk = TRUE;
                        break;
                    }
                } else if (AddressFamily == ADDRESS_FAMILY_IPV6 && targetIpV6 != NULL) {
                    if (MatchIPv6Prefix(targetIpV6, g_Rules[i].IpAddresses[j].V6.Address,
                                       g_Rules[i].IpAddresses[j].V6.PrefixLength)) {
                        ipOk = TRUE;
                        break;
                    }
                }
            }

            // Apply action based on filters
            switch (g_Rules[i].Action) {
                case FirewallActionBlock:
                    // If no filters specified -> block ALL traffic
                    // If filters specified -> block only matching ports/IPs
                    if (portOk && ipOk) {
                        allowed = FALSE;
                    }
                    break;
                case FirewallActionAllow:
                    allowed = TRUE;
                    break;
                case FirewallActionAllowRestricted:
                    allowed = portOk && ipOk;  // Only allow if ports AND IP match
                    break;
            }
            break;
        }
    }

    KeReleaseSpinLock(&g_RulesLock, oldIrql);
    return allowed;
}

// ALE Classify function
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID NTAPI AleClassifyFn(
    _In_ const FWPS_INCOMING_VALUES0* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    _Inout_opt_ void* layerData,
    _In_ const FWPS_FILTER0* filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT0* classifyOut)
{
    UNREFERENCED_PARAMETER(layerData);
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(flowContext);

    PEPROCESS currentProcess = NULL;
    ULONG processId = 0;
    CHAR processName[64] = { 0 };  // Increased from 16 to support long process names
    USHORT addressFamily = ADDRESS_FAMILY_IPV4;
    // IPv4 addresses
    ULONG localIpV4 = 0, remoteIpV4 = 0;
    // IPv6 addresses
    UCHAR localIpV6[16] = { 0 };
    UCHAR remoteIpV6[16] = { 0 };
    USHORT localPort = 0, remotePort = 0;
    BOOLEAN shouldBlock = FALSE;
    UCHAR protocol = 0, direction = 0;
    NTSTATUS status;

    if (inMetaValues->currentMetadataValues & FWPS_METADATA_FIELD_PROCESS_ID) {
        HANDLE pid = (HANDLE)(ULONG_PTR)inMetaValues->processId;
        processId = (ULONG)(ULONG_PTR)pid;
        
        if (pid != NULL && pid != (HANDLE)-1) {
            status = PsLookupProcessByProcessId(pid, &currentProcess);
            if (NT_SUCCESS(status) && currentProcess != NULL) {
                GetProcessNameA(currentProcess, processName, sizeof(processName));
                ObDereferenceObject(currentProcess);
            }
        }
    }

    if (processName[0] == '\0') {
        processName[0] = 'S'; processName[1] = 'y'; processName[2] = 's';
        processName[3] = 't'; processName[4] = 'e'; processName[5] = 'm';
        processName[6] = '\0';
    }

    // IPv4 CONNECT layer
    if (inFixedValues->layerId == FWPS_LAYER_ALE_AUTH_CONNECT_V4) {
        addressFamily = ADDRESS_FAMILY_IPV4;
        direction = 0;
        localIpV4 = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_ADDRESS].value.uint32;
        localPort = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_PORT].value.uint16;
        remoteIpV4 = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_ADDRESS].value.uint32;
        remotePort = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_PORT].value.uint16;
        protocol = (UCHAR)inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_PROTOCOL].value.uint8;
    }
    // IPv4 RECV_ACCEPT layer
    else if (inFixedValues->layerId == FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V4) {
        addressFamily = ADDRESS_FAMILY_IPV4;
        direction = 1;
        localIpV4 = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_LOCAL_ADDRESS].value.uint32;
        localPort = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_LOCAL_PORT].value.uint16;
        remoteIpV4 = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_REMOTE_ADDRESS].value.uint32;
        remotePort = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_REMOTE_PORT].value.uint16;
        protocol = (UCHAR)inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_PROTOCOL].value.uint8;
    }
    // IPv6 CONNECT layer
    else if (inFixedValues->layerId == FWPS_LAYER_ALE_AUTH_CONNECT_V6) {
        addressFamily = ADDRESS_FAMILY_IPV6;
        direction = 0;
        FWP_BYTE_ARRAY16* localAddr = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_LOCAL_ADDRESS].value.byteArray16;
        FWP_BYTE_ARRAY16* remoteAddr = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_ADDRESS].value.byteArray16;
        if (localAddr) RtlCopyMemory(localIpV6, localAddr->byteArray16, 16);
        if (remoteAddr) RtlCopyMemory(remoteIpV6, remoteAddr->byteArray16, 16);
        localPort = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_LOCAL_PORT].value.uint16;
        remotePort = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_PORT].value.uint16;
        protocol = (UCHAR)inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_PROTOCOL].value.uint8;
    }
    // IPv6 RECV_ACCEPT layer
    else if (inFixedValues->layerId == FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V6) {
        addressFamily = ADDRESS_FAMILY_IPV6;
        direction = 1;
        FWP_BYTE_ARRAY16* localAddr = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_LOCAL_ADDRESS].value.byteArray16;
        FWP_BYTE_ARRAY16* remoteAddr = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_REMOTE_ADDRESS].value.byteArray16;
        if (localAddr) RtlCopyMemory(localIpV6, localAddr->byteArray16, 16);
        if (remoteAddr) RtlCopyMemory(remoteIpV6, remoteAddr->byteArray16, 16);
        localPort = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_LOCAL_PORT].value.uint16;
        remotePort = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_REMOTE_PORT].value.uint16;
        protocol = (UCHAR)inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_PROTOCOL].value.uint8;
    }

    if (g_IsFilteringEnabled) {
        // Check blocked apps list first
        BOOLEAN appBlocked = IsAppBlockedByPid(processId) || IsAppBlockedByName(processName);

        // Single pass through ALL rules in order - first matching rule wins
        // ALLOW rules can override app blocking
        KIRQL ruleIrql;
        KeAcquireSpinLock(&g_RulesLock, &ruleIrql);

        BOOLEAN ruleMatched = FALSE;
        ULONG ri, rj;
        for (ri = 0; ri < g_RuleCount && !ruleMatched; ri++) {
            if (!g_Rules[ri].IsActive) continue;

            // Check if rule matches this process (by PID, name, or wildcard)
            BOOLEAN processMatch = FALSE;
            if (g_Rules[ri].ApplicationPath[0] == L'\0' || g_Rules[ri].ApplicationPath[0] == L'*') {
                processMatch = TRUE;  // Wildcard rule - matches all
            } else if (g_Rules[ri].ProcessId != 0 && g_Rules[ri].ProcessId == processId) {
                processMatch = TRUE;  // PID match
            } else {
                // Name match - extract name from rule path
                WCHAR ruleName[64] = { 0 };
                const WCHAR* lastSlash = wcsrchr(g_Rules[ri].ApplicationPath, L'\\');
                const WCHAR* fileName = lastSlash ? lastSlash + 1 : g_Rules[ri].ApplicationPath;
                wcsncpy(ruleName, fileName, 63);
                // Remove .exe extension for comparison
                WCHAR* dot = wcsrchr(ruleName, L'.');
                if (dot) *dot = L'\0';

                // Convert process name to wide for comparison
                WCHAR procNameW[64] = { 0 };
                for (int ci = 0; ci < 63 && processName[ci]; ci++)
                    procNameW[ci] = (WCHAR)processName[ci];

                if (_wcsnicmp(ruleName, procNameW, 63) == 0)
                    processMatch = TRUE;
            }

            if (!processMatch) continue;

            // Check direction
            if (g_Rules[ri].Direction == TrafficDirectionInput && direction != 1) continue;
            if (g_Rules[ri].Direction == TrafficDirectionOutput && direction != 0) continue;

            // Determine target IP/port based on direction
            ULONG targetIpV4;
            PUCHAR targetIpV6;
            USHORT targetPort;
            if (g_Rules[ri].Direction == TrafficDirectionInput) {
                targetIpV4 = remoteIpV4; targetIpV6 = remoteIpV6; targetPort = localPort;
            } else {
                targetIpV4 = remoteIpV4; targetIpV6 = remoteIpV6; targetPort = remotePort;
            }

            // Check port filter
            BOOLEAN portOk = (g_Rules[ri].PortRangeCount == 0);
            for (rj = 0; rj < g_Rules[ri].PortRangeCount; rj++) {
                if (targetPort >= g_Rules[ri].PortRanges[rj].StartPort &&
                    targetPort <= g_Rules[ri].PortRanges[rj].EndPort) {
                    portOk = TRUE; break;
                }
            }

            // Check IP filter
            BOOLEAN ipOk = (g_Rules[ri].IpAddressCount == 0);
            for (rj = 0; rj < g_Rules[ri].IpAddressCount; rj++) {
                if (g_Rules[ri].IpAddresses[rj].AddressFamily != addressFamily) continue;
                if (addressFamily == ADDRESS_FAMILY_IPV4) {
                    ULONG maskedT = targetIpV4 & g_Rules[ri].IpAddresses[rj].V4.Mask;
                    ULONG maskedR = g_Rules[ri].IpAddresses[rj].V4.Address & g_Rules[ri].IpAddresses[rj].V4.Mask;
                    if (maskedT == maskedR) { ipOk = TRUE; break; }
                } else if (addressFamily == ADDRESS_FAMILY_IPV6 && targetIpV6 != NULL) {
                    if (MatchIPv6Prefix(targetIpV6, g_Rules[ri].IpAddresses[rj].V6.Address,
                                       g_Rules[ri].IpAddresses[rj].V6.PrefixLength)) { ipOk = TRUE; break; }
                }
            }

            // Apply action - first matching rule wins
            switch (g_Rules[ri].Action) {
                case FirewallActionBlock:
                    if (portOk && ipOk) {
                        shouldBlock = TRUE; ruleMatched = TRUE;
                        KfwLog("ALE BLOCK rule#%u proc=%s port=%u", ri, processName, remotePort);
                    }
                    break;
                case FirewallActionAllow:
                    if (portOk && ipOk) {
                        shouldBlock = FALSE; ruleMatched = TRUE;
                        KfwLog("ALE ALLOW rule#%u proc=%s port=%u", ri, processName, remotePort);
                    }
                    break;
                case FirewallActionAllowRestricted:
                    if (portOk && ipOk) { shouldBlock = FALSE; ruleMatched = TRUE; }
                    else { shouldBlock = TRUE; ruleMatched = TRUE; }
                    break;
            }
        }
        KeReleaseSpinLock(&g_RulesLock, ruleIrql);

        // If no rule matched, fall back to app block list
        if (!ruleMatched && appBlocked) {
            shouldBlock = TRUE;
            KfwLog("ALE NORULE appBlocked proc=%s port=%u", processName, remotePort);
        }
    }

    // Cache for Stream/Datagram layers - blocking will happen there with packet data
    AddToConnCacheUnified(addressFamily, localIpV4, localIpV6, localPort,
                          remoteIpV4, remoteIpV6, remotePort, processId, processName, shouldBlock, direction);

    // Always permit at ALE layer - blocking happens at Stream/Datagram with packet data
    // This allows us to capture packet contents even for blocked connections
    classifyOut->actionType = FWP_ACTION_PERMIT;
}

// Stream/Datagram Classify function - has packet data
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID NTAPI DataClassifyFn(
    _In_ const FWPS_INCOMING_VALUES0* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    _Inout_opt_ void* layerData,
    _In_ const FWPS_FILTER0* filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT0* classifyOut)
{
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(flowContext);

    ULONG processId = 0;
    CHAR processName[64] = { 0 };  // Increased from 16 to support long process names
    USHORT addressFamily = ADDRESS_FAMILY_IPV4;
    // IPv4 addresses
    ULONG localIpV4 = 0, remoteIpV4 = 0;
    // IPv6 addresses
    UCHAR localIpV6[16] = { 0 };
    UCHAR remoteIpV6[16] = { 0 };
    USHORT localPort = 0, remotePort = 0;
    BOOLEAN shouldBlock = FALSE;
    UCHAR protocol = 0, direction = 0;
    PUCHAR packetData = NULL;
    USHORT packetLen = 0;

    // Allocate buffer for packet data
    packetData = (PUCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, ETW_MAX_PACKET_DATA, 'wfPD');
    if (packetData == NULL) {
        // Can't allocate, just permit without logging data
        classifyOut->actionType = FWP_ACTION_PERMIT;
        return;
    }
    RtlZeroMemory(packetData, ETW_MAX_PACKET_DATA);

    // Stream layer IPv4 (TCP)
    if (inFixedValues->layerId == FWPS_LAYER_STREAM_V4) {
        addressFamily = ADDRESS_FAMILY_IPV4;
        protocol = 6; // TCP
        localIpV4 = inFixedValues->incomingValue[FWPS_FIELD_STREAM_V4_IP_LOCAL_ADDRESS].value.uint32;
        localPort = inFixedValues->incomingValue[FWPS_FIELD_STREAM_V4_IP_LOCAL_PORT].value.uint16;
        remoteIpV4 = inFixedValues->incomingValue[FWPS_FIELD_STREAM_V4_IP_REMOTE_ADDRESS].value.uint32;
        remotePort = inFixedValues->incomingValue[FWPS_FIELD_STREAM_V4_IP_REMOTE_PORT].value.uint16;
        direction = (inFixedValues->incomingValue[FWPS_FIELD_STREAM_V4_DIRECTION].value.uint32 == FWP_DIRECTION_OUTBOUND) ? 0 : 1;
        
        // Get stream data
        FWPS_STREAM_CALLOUT_IO_PACKET0* streamPacket = (FWPS_STREAM_CALLOUT_IO_PACKET0*)layerData;
        if (streamPacket != NULL && streamPacket->streamData != NULL) {
            FWPS_STREAM_DATA0* streamData = streamPacket->streamData;
            if (streamData->dataLength > 0 && streamData->netBufferListChain != NULL) {
                NET_BUFFER_LIST* nbl = streamData->netBufferListChain;
                NET_BUFFER* nb = NET_BUFFER_LIST_FIRST_NB(nbl);
                if (nb != NULL) {
                    PMDL mdl = NET_BUFFER_CURRENT_MDL(nb);
                    if (mdl != NULL) {
                        PVOID buffer = MmGetSystemAddressForMdlSafe(mdl, NormalPagePriority | MdlMappingNoExecute);
                        if (buffer != NULL) {
                            ULONG offset = NET_BUFFER_CURRENT_MDL_OFFSET(nb);
                            ULONG mdlLen = MmGetMdlByteCount(mdl);
                            if (offset < mdlLen) {
                                ULONG available = mdlLen - offset;
                                ULONG toCopy = min(available, ETW_MAX_PACKET_DATA);
                                RtlCopyMemory(packetData, (PUCHAR)buffer + offset, toCopy);
                                packetLen = (USHORT)toCopy;
                            }
                        }
                    }
                }
            }
        }
    }
    // Datagram layer IPv4 (UDP)
    else if (inFixedValues->layerId == FWPS_LAYER_DATAGRAM_DATA_V4) {
        addressFamily = ADDRESS_FAMILY_IPV4;
        protocol = 17; // UDP
        localIpV4 = inFixedValues->incomingValue[FWPS_FIELD_DATAGRAM_DATA_V4_IP_LOCAL_ADDRESS].value.uint32;
        localPort = inFixedValues->incomingValue[FWPS_FIELD_DATAGRAM_DATA_V4_IP_LOCAL_PORT].value.uint16;
        remoteIpV4 = inFixedValues->incomingValue[FWPS_FIELD_DATAGRAM_DATA_V4_IP_REMOTE_ADDRESS].value.uint32;
        remotePort = inFixedValues->incomingValue[FWPS_FIELD_DATAGRAM_DATA_V4_IP_REMOTE_PORT].value.uint16;
        direction = (inFixedValues->incomingValue[FWPS_FIELD_DATAGRAM_DATA_V4_DIRECTION].value.uint32 == FWP_DIRECTION_OUTBOUND) ? 0 : 1;
        
        // Get datagram data
        NET_BUFFER_LIST* nbl = (NET_BUFFER_LIST*)layerData;
        if (nbl != NULL) {
            NET_BUFFER* nb = NET_BUFFER_LIST_FIRST_NB(nbl);
            if (nb != NULL) {
                PMDL mdl = NET_BUFFER_CURRENT_MDL(nb);
                if (mdl != NULL) {
                    PVOID buffer = MmGetSystemAddressForMdlSafe(mdl, NormalPagePriority | MdlMappingNoExecute);
                    if (buffer != NULL) {
                        ULONG offset = NET_BUFFER_CURRENT_MDL_OFFSET(nb);
                        ULONG mdlLen = MmGetMdlByteCount(mdl);
                        if (offset < mdlLen) {
                            ULONG available = mdlLen - offset;
                            ULONG toCopy = min(available, ETW_MAX_PACKET_DATA);
                            RtlCopyMemory(packetData, (PUCHAR)buffer + offset, toCopy);
                            packetLen = (USHORT)toCopy;
                        }
                    }
                }
            }
        }
    }
    // Stream layer IPv6 (TCP)
    else if (inFixedValues->layerId == FWPS_LAYER_STREAM_V6) {
        addressFamily = ADDRESS_FAMILY_IPV6;
        protocol = 6; // TCP
        FWP_BYTE_ARRAY16* localAddr = inFixedValues->incomingValue[FWPS_FIELD_STREAM_V6_IP_LOCAL_ADDRESS].value.byteArray16;
        FWP_BYTE_ARRAY16* remoteAddr = inFixedValues->incomingValue[FWPS_FIELD_STREAM_V6_IP_REMOTE_ADDRESS].value.byteArray16;
        if (localAddr) RtlCopyMemory(localIpV6, localAddr->byteArray16, 16);
        if (remoteAddr) RtlCopyMemory(remoteIpV6, remoteAddr->byteArray16, 16);
        localPort = inFixedValues->incomingValue[FWPS_FIELD_STREAM_V6_IP_LOCAL_PORT].value.uint16;
        remotePort = inFixedValues->incomingValue[FWPS_FIELD_STREAM_V6_IP_REMOTE_PORT].value.uint16;
        direction = (inFixedValues->incomingValue[FWPS_FIELD_STREAM_V6_DIRECTION].value.uint32 == FWP_DIRECTION_OUTBOUND) ? 0 : 1;

        // Get stream data (same as IPv4)
        FWPS_STREAM_CALLOUT_IO_PACKET0* streamPacket = (FWPS_STREAM_CALLOUT_IO_PACKET0*)layerData;
        if (streamPacket != NULL && streamPacket->streamData != NULL) {
            FWPS_STREAM_DATA0* streamData = streamPacket->streamData;
            if (streamData->dataLength > 0 && streamData->netBufferListChain != NULL) {
                NET_BUFFER_LIST* nbl = streamData->netBufferListChain;
                NET_BUFFER* nb = NET_BUFFER_LIST_FIRST_NB(nbl);
                if (nb != NULL) {
                    PMDL mdl = NET_BUFFER_CURRENT_MDL(nb);
                    if (mdl != NULL) {
                        PVOID buffer = MmGetSystemAddressForMdlSafe(mdl, NormalPagePriority | MdlMappingNoExecute);
                        if (buffer != NULL) {
                            ULONG offset = NET_BUFFER_CURRENT_MDL_OFFSET(nb);
                            ULONG mdlLen = MmGetMdlByteCount(mdl);
                            if (offset < mdlLen) {
                                ULONG available = mdlLen - offset;
                                ULONG toCopy = min(available, ETW_MAX_PACKET_DATA);
                                RtlCopyMemory(packetData, (PUCHAR)buffer + offset, toCopy);
                                packetLen = (USHORT)toCopy;
                            }
                        }
                    }
                }
            }
        }
    }
    // Datagram layer IPv6 (UDP)
    else if (inFixedValues->layerId == FWPS_LAYER_DATAGRAM_DATA_V6) {
        addressFamily = ADDRESS_FAMILY_IPV6;
        protocol = 17; // UDP
        FWP_BYTE_ARRAY16* localAddr = inFixedValues->incomingValue[FWPS_FIELD_DATAGRAM_DATA_V6_IP_LOCAL_ADDRESS].value.byteArray16;
        FWP_BYTE_ARRAY16* remoteAddr = inFixedValues->incomingValue[FWPS_FIELD_DATAGRAM_DATA_V6_IP_REMOTE_ADDRESS].value.byteArray16;
        if (localAddr) RtlCopyMemory(localIpV6, localAddr->byteArray16, 16);
        if (remoteAddr) RtlCopyMemory(remoteIpV6, remoteAddr->byteArray16, 16);
        localPort = inFixedValues->incomingValue[FWPS_FIELD_DATAGRAM_DATA_V6_IP_LOCAL_PORT].value.uint16;
        remotePort = inFixedValues->incomingValue[FWPS_FIELD_DATAGRAM_DATA_V6_IP_REMOTE_PORT].value.uint16;
        direction = (inFixedValues->incomingValue[FWPS_FIELD_DATAGRAM_DATA_V6_DIRECTION].value.uint32 == FWP_DIRECTION_OUTBOUND) ? 0 : 1;

        // Get datagram data (same as IPv4)
        NET_BUFFER_LIST* nbl = (NET_BUFFER_LIST*)layerData;
        if (nbl != NULL) {
            NET_BUFFER* nb = NET_BUFFER_LIST_FIRST_NB(nbl);
            if (nb != NULL) {
                PMDL mdl = NET_BUFFER_CURRENT_MDL(nb);
                if (mdl != NULL) {
                    PVOID buffer = MmGetSystemAddressForMdlSafe(mdl, NormalPagePriority | MdlMappingNoExecute);
                    if (buffer != NULL) {
                        ULONG offset = NET_BUFFER_CURRENT_MDL_OFFSET(nb);
                        ULONG mdlLen = MmGetMdlByteCount(mdl);
                        if (offset < mdlLen) {
                            ULONG available = mdlLen - offset;
                            ULONG toCopy = min(available, ETW_MAX_PACKET_DATA);
                            RtlCopyMemory(packetData, (PUCHAR)buffer + offset, toCopy);
                            packetLen = (USHORT)toCopy;
                        }
                    }
                }
            }
        }
    }

    // Lookup cache for process info ONLY (not block decision)
    {
        BOOLEAN cachedBlock = FALSE;
        BOOLEAN found = LookupConnCacheUnified(addressFamily, localIpV4, localIpV6, localPort,
                                               remoteIpV4, remoteIpV6, remotePort, &processId, processName, &cachedBlock);
        // Ignore cachedBlock - we always re-evaluate rules below
        (void)cachedBlock;
        (void)found;
    }

    // Fallback process info
    if (processId == 0 && (inMetaValues->currentMetadataValues & FWPS_METADATA_FIELD_PROCESS_ID)) {
        processId = (ULONG)(ULONG_PTR)inMetaValues->processId;
    }
    if (processName[0] == '\0') {
        processName[0] = 'S'; processName[1] = 'y'; processName[2] = 's';
        processName[3] = 't'; processName[4] = 'e'; processName[5] = 'm';
        processName[6] = '\0';
    }

    // Get process name if still unknown
    if (processId != 0 && processName[0] == 'S' && processName[1] == 'y' && processName[2] == 's' &&
        processName[3] == 't' && processName[4] == 'e' && processName[5] == 'm' && processName[6] == '\0') {
        PEPROCESS currentProcess = NULL;
        NTSTATUS status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)processId, &currentProcess);
        if (NT_SUCCESS(status) && currentProcess != NULL) {
            GetProcessNameA(currentProcess, processName, sizeof(processName));
            ObDereferenceObject(currentProcess);
        }
    }

    // Always evaluate rules - single pass, first matching rule wins
    {
        if (g_IsFilteringEnabled) {
            BOOLEAN appBlocked = FALSE;
            if (processId != 0) appBlocked = IsAppBlockedByPid(processId);
            if (!appBlocked) appBlocked = IsAppBlockedByName(processName);

            KIRQL ruleIrql;
            KeAcquireSpinLock(&g_RulesLock, &ruleIrql);

            BOOLEAN ruleMatched = FALSE;
            ULONG ri, rj;
            for (ri = 0; ri < g_RuleCount && !ruleMatched; ri++) {
                if (!g_Rules[ri].IsActive) continue;

                // Match process
                BOOLEAN processMatch = FALSE;
                if (g_Rules[ri].ApplicationPath[0] == L'\0' || g_Rules[ri].ApplicationPath[0] == L'*') {
                    processMatch = TRUE;
                } else if (g_Rules[ri].ProcessId != 0 && g_Rules[ri].ProcessId == processId) {
                    processMatch = TRUE;
                } else {
                    WCHAR ruleName[64] = { 0 };
                    const WCHAR* lastSlash = wcsrchr(g_Rules[ri].ApplicationPath, L'\\');
                    const WCHAR* fileName = lastSlash ? lastSlash + 1 : g_Rules[ri].ApplicationPath;
                    wcsncpy(ruleName, fileName, 63);
                    WCHAR* dot = wcsrchr(ruleName, L'.');
                    if (dot) *dot = L'\0';
                    WCHAR procNameW[64] = { 0 };
                    for (int ci = 0; ci < 63 && processName[ci]; ci++)
                        procNameW[ci] = (WCHAR)processName[ci];
                    if (_wcsnicmp(ruleName, procNameW, 63) == 0)
                        processMatch = TRUE;
                }
                if (!processMatch) continue;

                // Check direction
                if (g_Rules[ri].Direction == TrafficDirectionInput && direction != 1) continue;
                if (g_Rules[ri].Direction == TrafficDirectionOutput && direction != 0) continue;

                ULONG targetIpV4; PUCHAR targetIpV6; USHORT targetPort;
                if (g_Rules[ri].Direction == TrafficDirectionInput) {
                    targetIpV4 = remoteIpV4; targetIpV6 = remoteIpV6; targetPort = localPort;
                } else {
                    targetIpV4 = remoteIpV4; targetIpV6 = remoteIpV6; targetPort = remotePort;
                }

                BOOLEAN portOk = (g_Rules[ri].PortRangeCount == 0);
                for (rj = 0; rj < g_Rules[ri].PortRangeCount; rj++) {
                    if (targetPort >= g_Rules[ri].PortRanges[rj].StartPort &&
                        targetPort <= g_Rules[ri].PortRanges[rj].EndPort) { portOk = TRUE; break; }
                }

                BOOLEAN ipOk = (g_Rules[ri].IpAddressCount == 0);
                for (rj = 0; rj < g_Rules[ri].IpAddressCount; rj++) {
                    if (g_Rules[ri].IpAddresses[rj].AddressFamily != addressFamily) continue;
                    if (addressFamily == ADDRESS_FAMILY_IPV4) {
                        ULONG maskedT = targetIpV4 & g_Rules[ri].IpAddresses[rj].V4.Mask;
                        ULONG maskedR = g_Rules[ri].IpAddresses[rj].V4.Address & g_Rules[ri].IpAddresses[rj].V4.Mask;
                        if (maskedT == maskedR) { ipOk = TRUE; break; }
                    } else if (addressFamily == ADDRESS_FAMILY_IPV6 && targetIpV6 != NULL) {
                        if (MatchIPv6Prefix(targetIpV6, g_Rules[ri].IpAddresses[rj].V6.Address,
                                           g_Rules[ri].IpAddresses[rj].V6.PrefixLength)) { ipOk = TRUE; break; }
                    }
                }

                switch (g_Rules[ri].Action) {
                    case FirewallActionBlock:
                        if (portOk && ipOk) {
                            shouldBlock = TRUE; ruleMatched = TRUE;
                            KfwLog("DATA BLOCK rule#%u proc=%s port=%u", ri, processName, targetPort);
                        }
                        break;
                    case FirewallActionAllow:
                        if (portOk && ipOk) {
                            shouldBlock = FALSE; ruleMatched = TRUE;
                            KfwLog("DATA ALLOW rule#%u proc=%s port=%u", ri, processName, targetPort);
                        }
                        break;
                    case FirewallActionAllowRestricted:
                        if (portOk && ipOk) { shouldBlock = FALSE; ruleMatched = TRUE; }
                        else { shouldBlock = TRUE; ruleMatched = TRUE; }
                        break;
                }
            }
            KeReleaseSpinLock(&g_RulesLock, ruleIrql);

            if (!ruleMatched && appBlocked) {
                shouldBlock = TRUE;
                KfwLog("DATA NORULE appBlocked proc=%s port=%u", processName, remotePort);
            }
            if (!ruleMatched && !appBlocked) {
                KfwLog("DATA PASS proc=%s port=%u", processName, remotePort);
            }
        }
    }

    // Update statistics
    if (shouldBlock) {
        InterlockedIncrement64(&g_PacketsBlocked);
    } else {
        InterlockedIncrement64(&g_PacketsAllowed);
    }

    // Update per-process statistics
    if (processName[0] != '\0') {
        KIRQL statsIrql;
        KeAcquireSpinLock(&g_StatsLock, &statsIrql);
        PPROCESS_STATS_ENTRY pStats = FindOrCreateProcessStats(processName);
        if (pStats != NULL) {
            if (direction == 0) { // Outbound
                pStats->PacketsSent++;
                pStats->BytesSent += packetLen;
            } else {
                pStats->PacketsRecv++;
                pStats->BytesRecv += packetLen;
            }
            if (shouldBlock) {
                pStats->PacketsBlocked++;
            }
        }
        KeReleaseSpinLock(&g_StatsLock, statsIrql);
    }

    // Log with packet data - now we have data even for blocked packets
    LogNetworkEventEtw(processId, processName, addressFamily,
                       localIpV4, localIpV6, localPort,
                       remoteIpV4, remoteIpV6, remotePort,
                       protocol, direction, shouldBlock,
                       packetData, packetLen);

    // Free packet data buffer
    if (packetData != NULL) {
        ExFreePoolWithTag(packetData, 'wfPD');
    }

    // Block or permit based on cache
    if (shouldBlock) {
        classifyOut->actionType = FWP_ACTION_BLOCK;
        classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
    } else {
        classifyOut->actionType = FWP_ACTION_PERMIT;
    }
}

// Notify function
NTSTATUS NTAPI NotifyFn(
    _In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType,
    _In_ const GUID* filterKey,
    _Inout_ FWPS_FILTER0* filter)
{
    UNREFERENCED_PARAMETER(notifyType);
    UNREFERENCED_PARAMETER(filterKey);
    UNREFERENCED_PARAMETER(filter);
    return STATUS_SUCCESS;
}

// Flow delete function
VOID NTAPI FlowDeleteFn(
    _In_ UINT16 layerId,
    _In_ UINT32 calloutId,
    _In_ UINT64 flowContext)
{
    UNREFERENCED_PARAMETER(layerId);
    UNREFERENCED_PARAMETER(calloutId);
    UNREFERENCED_PARAMETER(flowContext);
}

// Register WFP callouts
NTSTATUS RegisterWfpCallouts(void)
{
    NTSTATUS status;
    FWPM_SESSION0 session = { 0 };
    FWPM_SUBLAYER0 sublayer = { 0 };
    FWPS_CALLOUT0 sCallout = { 0 };
    FWPM_CALLOUT0 mCallout = { 0 };
    FWPM_FILTER0 filter = { 0 };

    session.flags = FWPM_SESSION_FLAG_DYNAMIC;

    status = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, &session, &g_EngineHandle);
    if (!NT_SUCCESS(status)) return status;

    status = FwpmTransactionBegin0(g_EngineHandle, 0);
    if (!NT_SUCCESS(status)) {
        FwpmEngineClose0(g_EngineHandle);
        return status;
    }

    // Sublayer
    sublayer.subLayerKey = FIREWALL_SUBLAYER_GUID;
    sublayer.displayData.name = L"Kernel Firewall ETW Sublayer";
    sublayer.weight = 0xFFFF;
    FwpmSubLayerAdd0(g_EngineHandle, &sublayer, NULL);

    // ALE Connect
    sCallout.calloutKey = FIREWALL_CALLOUT_GUID_CONNECT;
    sCallout.classifyFn = AleClassifyFn;
    sCallout.notifyFn = NotifyFn;
    sCallout.flowDeleteFn = FlowDeleteFn;
    status = FwpsCalloutRegister0(g_DeviceObject, &sCallout, &g_CalloutIdConnect);
    if (!NT_SUCCESS(status)) goto cleanup;

    mCallout.calloutKey = FIREWALL_CALLOUT_GUID_CONNECT;
    mCallout.displayData.name = L"ETW Firewall Connect";
    mCallout.applicableLayer = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    FwpmCalloutAdd0(g_EngineHandle, &mCallout, NULL, NULL);

    filter.filterKey = FIREWALL_FILTER_GUID_CONNECT;
    filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    filter.displayData.name = L"ETW Connect Filter";
    filter.action.type = FWP_ACTION_CALLOUT_TERMINATING;
    filter.action.calloutKey = FIREWALL_CALLOUT_GUID_CONNECT;
    filter.subLayerKey = FIREWALL_SUBLAYER_GUID;
    filter.weight.type = FWP_UINT8;
    filter.weight.uint8 = 0xF;
    FwpmFilterAdd0(g_EngineHandle, &filter, NULL, &g_FilterIdConnect);

    // ALE Recv
    RtlZeroMemory(&sCallout, sizeof(sCallout));
    sCallout.calloutKey = FIREWALL_CALLOUT_GUID_RECV;
    sCallout.classifyFn = AleClassifyFn;
    sCallout.notifyFn = NotifyFn;
    sCallout.flowDeleteFn = FlowDeleteFn;
    status = FwpsCalloutRegister0(g_DeviceObject, &sCallout, &g_CalloutIdRecv);
    if (!NT_SUCCESS(status)) goto cleanup;

    RtlZeroMemory(&mCallout, sizeof(mCallout));
    mCallout.calloutKey = FIREWALL_CALLOUT_GUID_RECV;
    mCallout.displayData.name = L"ETW Firewall Recv";
    mCallout.applicableLayer = FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4;
    FwpmCalloutAdd0(g_EngineHandle, &mCallout, NULL, NULL);

    RtlZeroMemory(&filter, sizeof(filter));
    filter.filterKey = FIREWALL_FILTER_GUID_RECV;
    filter.layerKey = FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4;
    filter.displayData.name = L"ETW Recv Filter";
    filter.action.type = FWP_ACTION_CALLOUT_TERMINATING;
    filter.action.calloutKey = FIREWALL_CALLOUT_GUID_RECV;
    filter.subLayerKey = FIREWALL_SUBLAYER_GUID;
    filter.weight.type = FWP_UINT8;
    filter.weight.uint8 = 0xF;
    FwpmFilterAdd0(g_EngineHandle, &filter, NULL, &g_FilterIdRecv);

    // Stream (TCP data)
    RtlZeroMemory(&sCallout, sizeof(sCallout));
    sCallout.calloutKey = FIREWALL_CALLOUT_GUID_STREAM;
    sCallout.classifyFn = DataClassifyFn;
    sCallout.notifyFn = NotifyFn;
    sCallout.flowDeleteFn = FlowDeleteFn;
    if (NT_SUCCESS(FwpsCalloutRegister0(g_DeviceObject, &sCallout, &g_CalloutIdStream))) {
        RtlZeroMemory(&mCallout, sizeof(mCallout));
        mCallout.calloutKey = FIREWALL_CALLOUT_GUID_STREAM;
        mCallout.displayData.name = L"ETW Stream";
        mCallout.applicableLayer = FWPM_LAYER_STREAM_V4;
        FwpmCalloutAdd0(g_EngineHandle, &mCallout, NULL, NULL);

        RtlZeroMemory(&filter, sizeof(filter));
        filter.filterKey = FIREWALL_FILTER_GUID_STREAM;
        filter.layerKey = FWPM_LAYER_STREAM_V4;
        filter.displayData.name = L"ETW Stream Filter";
        filter.action.type = FWP_ACTION_CALLOUT_TERMINATING;
        filter.action.calloutKey = FIREWALL_CALLOUT_GUID_STREAM;
        filter.subLayerKey = FIREWALL_SUBLAYER_GUID;
        filter.weight.type = FWP_UINT8;
        filter.weight.uint8 = 0xF;
        FwpmFilterAdd0(g_EngineHandle, &filter, NULL, &g_FilterIdStream);
    }

    // Datagram (UDP data)
    RtlZeroMemory(&sCallout, sizeof(sCallout));
    sCallout.calloutKey = FIREWALL_CALLOUT_GUID_DATAGRAM;
    sCallout.classifyFn = DataClassifyFn;
    sCallout.notifyFn = NotifyFn;
    sCallout.flowDeleteFn = FlowDeleteFn;
    if (NT_SUCCESS(FwpsCalloutRegister0(g_DeviceObject, &sCallout, &g_CalloutIdDatagram))) {
        RtlZeroMemory(&mCallout, sizeof(mCallout));
        mCallout.calloutKey = FIREWALL_CALLOUT_GUID_DATAGRAM;
        mCallout.displayData.name = L"ETW Datagram";
        mCallout.applicableLayer = FWPM_LAYER_DATAGRAM_DATA_V4;
        FwpmCalloutAdd0(g_EngineHandle, &mCallout, NULL, NULL);

        RtlZeroMemory(&filter, sizeof(filter));
        filter.filterKey = FIREWALL_FILTER_GUID_DATAGRAM;
        filter.layerKey = FWPM_LAYER_DATAGRAM_DATA_V4;
        filter.displayData.name = L"ETW Datagram Filter";
        filter.action.type = FWP_ACTION_CALLOUT_TERMINATING;
        filter.action.calloutKey = FIREWALL_CALLOUT_GUID_DATAGRAM;
        filter.subLayerKey = FIREWALL_SUBLAYER_GUID;
        filter.weight.type = FWP_UINT8;
        filter.weight.uint8 = 0xF;
        FwpmFilterAdd0(g_EngineHandle, &filter, NULL, &g_FilterIdDatagram);
    }

    // ====== IPv6 Layers Registration ======

    // ALE Connect V6
    RtlZeroMemory(&sCallout, sizeof(sCallout));
    sCallout.calloutKey = FIREWALL_CALLOUT_GUID_CONNECT_V6;
    sCallout.classifyFn = AleClassifyFn;
    sCallout.notifyFn = NotifyFn;
    sCallout.flowDeleteFn = FlowDeleteFn;
    status = FwpsCalloutRegister0(g_DeviceObject, &sCallout, &g_CalloutIdConnect_V6);
    if (!NT_SUCCESS(status)) goto cleanup;

    RtlZeroMemory(&mCallout, sizeof(mCallout));
    mCallout.calloutKey = FIREWALL_CALLOUT_GUID_CONNECT_V6;
    mCallout.displayData.name = L"ETW Firewall Connect V6";
    mCallout.applicableLayer = FWPM_LAYER_ALE_AUTH_CONNECT_V6;
    FwpmCalloutAdd0(g_EngineHandle, &mCallout, NULL, NULL);

    RtlZeroMemory(&filter, sizeof(filter));
    filter.filterKey = FIREWALL_FILTER_GUID_CONNECT_V6;
    filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V6;
    filter.displayData.name = L"ETW Connect Filter V6";
    filter.action.type = FWP_ACTION_CALLOUT_TERMINATING;
    filter.action.calloutKey = FIREWALL_CALLOUT_GUID_CONNECT_V6;
    filter.subLayerKey = FIREWALL_SUBLAYER_GUID;
    filter.weight.type = FWP_UINT8;
    filter.weight.uint8 = 0xF;
    FwpmFilterAdd0(g_EngineHandle, &filter, NULL, &g_FilterIdConnect_V6);

    // ALE Recv V6
    RtlZeroMemory(&sCallout, sizeof(sCallout));
    sCallout.calloutKey = FIREWALL_CALLOUT_GUID_RECV_V6;
    sCallout.classifyFn = AleClassifyFn;
    sCallout.notifyFn = NotifyFn;
    sCallout.flowDeleteFn = FlowDeleteFn;
    status = FwpsCalloutRegister0(g_DeviceObject, &sCallout, &g_CalloutIdRecv_V6);
    if (!NT_SUCCESS(status)) goto cleanup;

    RtlZeroMemory(&mCallout, sizeof(mCallout));
    mCallout.calloutKey = FIREWALL_CALLOUT_GUID_RECV_V6;
    mCallout.displayData.name = L"ETW Firewall Recv V6";
    mCallout.applicableLayer = FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6;
    FwpmCalloutAdd0(g_EngineHandle, &mCallout, NULL, NULL);

    RtlZeroMemory(&filter, sizeof(filter));
    filter.filterKey = FIREWALL_FILTER_GUID_RECV_V6;
    filter.layerKey = FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6;
    filter.displayData.name = L"ETW Recv Filter V6";
    filter.action.type = FWP_ACTION_CALLOUT_TERMINATING;
    filter.action.calloutKey = FIREWALL_CALLOUT_GUID_RECV_V6;
    filter.subLayerKey = FIREWALL_SUBLAYER_GUID;
    filter.weight.type = FWP_UINT8;
    filter.weight.uint8 = 0xF;
    FwpmFilterAdd0(g_EngineHandle, &filter, NULL, &g_FilterIdRecv_V6);

    // Stream V6 (TCP data)
    RtlZeroMemory(&sCallout, sizeof(sCallout));
    sCallout.calloutKey = FIREWALL_CALLOUT_GUID_STREAM_V6;
    sCallout.classifyFn = DataClassifyFn;
    sCallout.notifyFn = NotifyFn;
    sCallout.flowDeleteFn = FlowDeleteFn;
    if (NT_SUCCESS(FwpsCalloutRegister0(g_DeviceObject, &sCallout, &g_CalloutIdStream_V6))) {
        RtlZeroMemory(&mCallout, sizeof(mCallout));
        mCallout.calloutKey = FIREWALL_CALLOUT_GUID_STREAM_V6;
        mCallout.displayData.name = L"ETW Stream V6";
        mCallout.applicableLayer = FWPM_LAYER_STREAM_V6;
        FwpmCalloutAdd0(g_EngineHandle, &mCallout, NULL, NULL);

        RtlZeroMemory(&filter, sizeof(filter));
        filter.filterKey = FIREWALL_FILTER_GUID_STREAM_V6;
        filter.layerKey = FWPM_LAYER_STREAM_V6;
        filter.displayData.name = L"ETW Stream Filter V6";
        filter.action.type = FWP_ACTION_CALLOUT_TERMINATING;
        filter.action.calloutKey = FIREWALL_CALLOUT_GUID_STREAM_V6;
        filter.subLayerKey = FIREWALL_SUBLAYER_GUID;
        filter.weight.type = FWP_UINT8;
        filter.weight.uint8 = 0xF;
        FwpmFilterAdd0(g_EngineHandle, &filter, NULL, &g_FilterIdStream_V6);
    }

    // Datagram V6 (UDP data)
    RtlZeroMemory(&sCallout, sizeof(sCallout));
    sCallout.calloutKey = FIREWALL_CALLOUT_GUID_DATAGRAM_V6;
    sCallout.classifyFn = DataClassifyFn;
    sCallout.notifyFn = NotifyFn;
    sCallout.flowDeleteFn = FlowDeleteFn;
    if (NT_SUCCESS(FwpsCalloutRegister0(g_DeviceObject, &sCallout, &g_CalloutIdDatagram_V6))) {
        RtlZeroMemory(&mCallout, sizeof(mCallout));
        mCallout.calloutKey = FIREWALL_CALLOUT_GUID_DATAGRAM_V6;
        mCallout.displayData.name = L"ETW Datagram V6";
        mCallout.applicableLayer = FWPM_LAYER_DATAGRAM_DATA_V6;
        FwpmCalloutAdd0(g_EngineHandle, &mCallout, NULL, NULL);

        RtlZeroMemory(&filter, sizeof(filter));
        filter.filterKey = FIREWALL_FILTER_GUID_DATAGRAM_V6;
        filter.layerKey = FWPM_LAYER_DATAGRAM_DATA_V6;
        filter.displayData.name = L"ETW Datagram Filter V6";
        filter.action.type = FWP_ACTION_CALLOUT_TERMINATING;
        filter.action.calloutKey = FIREWALL_CALLOUT_GUID_DATAGRAM_V6;
        filter.subLayerKey = FIREWALL_SUBLAYER_GUID;
        filter.weight.type = FWP_UINT8;
        filter.weight.uint8 = 0xF;
        FwpmFilterAdd0(g_EngineHandle, &filter, NULL, &g_FilterIdDatagram_V6);
    }

    status = FwpmTransactionCommit0(g_EngineHandle);
    if (NT_SUCCESS(status)) {
        g_IsFilteringEnabled = TRUE;
        return STATUS_SUCCESS;
    }

cleanup:
    FwpmTransactionAbort0(g_EngineHandle);
    FwpmEngineClose0(g_EngineHandle);
    return status;
}

// Unregister
void UnregisterWfpCallouts(void)
{
    g_IsFilteringEnabled = FALSE;

    if (g_EngineHandle != NULL) {
        // Delete IPv4 filters
        if (g_FilterIdConnect) FwpmFilterDeleteById0(g_EngineHandle, g_FilterIdConnect);
        if (g_FilterIdRecv) FwpmFilterDeleteById0(g_EngineHandle, g_FilterIdRecv);
        if (g_FilterIdStream) FwpmFilterDeleteById0(g_EngineHandle, g_FilterIdStream);
        if (g_FilterIdDatagram) FwpmFilterDeleteById0(g_EngineHandle, g_FilterIdDatagram);

        // Delete IPv6 filters
        if (g_FilterIdConnect_V6) FwpmFilterDeleteById0(g_EngineHandle, g_FilterIdConnect_V6);
        if (g_FilterIdRecv_V6) FwpmFilterDeleteById0(g_EngineHandle, g_FilterIdRecv_V6);
        if (g_FilterIdStream_V6) FwpmFilterDeleteById0(g_EngineHandle, g_FilterIdStream_V6);
        if (g_FilterIdDatagram_V6) FwpmFilterDeleteById0(g_EngineHandle, g_FilterIdDatagram_V6);

        // Delete IPv4 callouts
        FwpmCalloutDeleteByKey0(g_EngineHandle, &FIREWALL_CALLOUT_GUID_CONNECT);
        FwpmCalloutDeleteByKey0(g_EngineHandle, &FIREWALL_CALLOUT_GUID_RECV);
        FwpmCalloutDeleteByKey0(g_EngineHandle, &FIREWALL_CALLOUT_GUID_STREAM);
        FwpmCalloutDeleteByKey0(g_EngineHandle, &FIREWALL_CALLOUT_GUID_DATAGRAM);

        // Delete IPv6 callouts
        FwpmCalloutDeleteByKey0(g_EngineHandle, &FIREWALL_CALLOUT_GUID_CONNECT_V6);
        FwpmCalloutDeleteByKey0(g_EngineHandle, &FIREWALL_CALLOUT_GUID_RECV_V6);
        FwpmCalloutDeleteByKey0(g_EngineHandle, &FIREWALL_CALLOUT_GUID_STREAM_V6);
        FwpmCalloutDeleteByKey0(g_EngineHandle, &FIREWALL_CALLOUT_GUID_DATAGRAM_V6);

        FwpmSubLayerDeleteByKey0(g_EngineHandle, &FIREWALL_SUBLAYER_GUID);
        FwpmEngineClose0(g_EngineHandle);
        g_EngineHandle = NULL;
    }

    // Unregister IPv4 callouts
    if (g_CalloutIdConnect) { FwpsCalloutUnregisterById0(g_CalloutIdConnect); g_CalloutIdConnect = 0; }
    if (g_CalloutIdRecv) { FwpsCalloutUnregisterById0(g_CalloutIdRecv); g_CalloutIdRecv = 0; }
    if (g_CalloutIdStream) { FwpsCalloutUnregisterById0(g_CalloutIdStream); g_CalloutIdStream = 0; }
    if (g_CalloutIdDatagram) { FwpsCalloutUnregisterById0(g_CalloutIdDatagram); g_CalloutIdDatagram = 0; }

    // Unregister IPv6 callouts
    if (g_CalloutIdConnect_V6) { FwpsCalloutUnregisterById0(g_CalloutIdConnect_V6); g_CalloutIdConnect_V6 = 0; }
    if (g_CalloutIdRecv_V6) { FwpsCalloutUnregisterById0(g_CalloutIdRecv_V6); g_CalloutIdRecv_V6 = 0; }
    if (g_CalloutIdStream_V6) { FwpsCalloutUnregisterById0(g_CalloutIdStream_V6); g_CalloutIdStream_V6 = 0; }
    if (g_CalloutIdDatagram_V6) { FwpsCalloutUnregisterById0(g_CalloutIdDatagram_V6); g_CalloutIdDatagram_V6 = 0; }
}

// IOCTL dispatch
NTSTATUS DriverDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status = STATUS_SUCCESS;
    ULONG_PTR information = 0;
    PVOID inputBuffer = Irp->AssociatedIrp.SystemBuffer;
    PVOID outputBuffer = Irp->AssociatedIrp.SystemBuffer;
    ULONG inputLength = irpSp->Parameters.DeviceIoControl.InputBufferLength;
    ULONG outputLength = irpSp->Parameters.DeviceIoControl.OutputBufferLength;
    KIRQL oldIrql;

    switch (irpSp->MajorFunction) {
        case IRP_MJ_CREATE:
        case IRP_MJ_CLOSE:
            status = STATUS_SUCCESS;
            break;

        case IRP_MJ_DEVICE_CONTROL:
            switch (irpSp->Parameters.DeviceIoControl.IoControlCode) {
                
                case IOCTL_FIREWALL_ADD_RULE:
                    if (inputLength >= sizeof(ADD_RULE_REQUEST) && outputLength >= sizeof(ULONG)) {
                        PADD_RULE_REQUEST req = (PADD_RULE_REQUEST)inputBuffer;
                        PULONG responseRuleId = (PULONG)outputBuffer;
                        KeAcquireSpinLock(&g_RulesLock, &oldIrql);
                        if (g_RuleCount < MAX_RULES) {
                            RtlCopyMemory(&g_Rules[g_RuleCount], &req->Rule, sizeof(FIREWALL_RULE));
                            g_Rules[g_RuleCount].RuleId = g_NextRuleId;
                            g_Rules[g_RuleCount].IsActive = TRUE;
                            *responseRuleId = g_NextRuleId;  // Return the created RuleId
                            g_NextRuleId++;
                            g_RuleCount++;
                            information = sizeof(ULONG);
                        } else {
                            status = STATUS_INSUFFICIENT_RESOURCES;
                        }
                        KeReleaseSpinLock(&g_RulesLock, oldIrql);
                        // Clear connection cache to force re-evaluation
                        ClearConnCache();
                    } else {
                        status = STATUS_BUFFER_TOO_SMALL;
                    }
                    break;

                case IOCTL_FIREWALL_REMOVE_RULE:
                    if (inputLength >= sizeof(REMOVE_RULE_REQUEST)) {
                        PREMOVE_RULE_REQUEST req = (PREMOVE_RULE_REQUEST)inputBuffer;
                        BOOLEAN removed = FALSE;
                        KeAcquireSpinLock(&g_RulesLock, &oldIrql);
                        for (ULONG i = 0; i < g_RuleCount; i++) {
                            if (g_Rules[i].RuleId == req->RuleId) {
                                if (i < g_RuleCount - 1) {
                                    RtlMoveMemory(&g_Rules[i], &g_Rules[i + 1], (g_RuleCount - i - 1) * sizeof(FIREWALL_RULE));
                                }
                                g_RuleCount--;
                                removed = TRUE;
                                break;
                            }
                        }
                        KeReleaseSpinLock(&g_RulesLock, oldIrql);
                        // Clear connection cache to force re-evaluation
                        if (removed) ClearConnCache();
                    }
                    break;

                case IOCTL_FIREWALL_CLEAR_RULES:
                    KeAcquireSpinLock(&g_RulesLock, &oldIrql);
                    g_RuleCount = 0;
                    KeReleaseSpinLock(&g_RulesLock, oldIrql);
                    // Clear connection cache to force re-evaluation
                    ClearConnCache();
                    break;

                case IOCTL_FIREWALL_GET_RULES:
                    if (outputLength >= sizeof(GET_RULES_RESPONSE)) {
                        PGET_RULES_RESPONSE resp = (PGET_RULES_RESPONSE)outputBuffer;
                        KeAcquireSpinLock(&g_RulesLock, &oldIrql);
                        resp->RuleCount = g_RuleCount;
                        RtlCopyMemory(resp->Rules, g_Rules, g_RuleCount * sizeof(FIREWALL_RULE));
                        KeReleaseSpinLock(&g_RulesLock, oldIrql);
                        information = sizeof(GET_RULES_RESPONSE);
                    }
                    break;

                case IOCTL_FIREWALL_ENABLE:
                    if (!g_IsFilteringEnabled) status = RegisterWfpCallouts();
                    break;

                case IOCTL_FIREWALL_DISABLE:
                    if (g_IsFilteringEnabled) UnregisterWfpCallouts();
                    break;

                case IOCTL_FIREWALL_GET_STATUS:
                    if (outputLength >= sizeof(FIREWALL_STATUS)) {
                        PFIREWALL_STATUS resp = (PFIREWALL_STATUS)outputBuffer;
                        resp->IsEnabled = g_IsFilteringEnabled;
                        resp->RuleCount = g_RuleCount;
                        resp->BlockedAppCount = g_BlockedAppCount;
                        resp->PacketsBlocked = (ULONG)g_PacketsBlocked;
                        resp->PacketsAllowed = (ULONG)g_PacketsAllowed;
                        information = sizeof(FIREWALL_STATUS);
                    }
                    break;

                case IOCTL_FIREWALL_BLOCK_APP:
                    if (inputLength >= sizeof(BLOCK_APP_REQUEST)) {
                        PBLOCK_APP_REQUEST req = (PBLOCK_APP_REQUEST)inputBuffer;
                        BOOLEAN added = FALSE;
                        KeAcquireSpinLock(&g_BlockedLock, &oldIrql);
                        if (g_BlockedAppCount < MAX_BLOCKED_APPS) {
                            RtlCopyMemory(g_BlockedApps[g_BlockedAppCount].ApplicationPath, req->ApplicationPath, sizeof(req->ApplicationPath));
                            g_BlockedApps[g_BlockedAppCount].ProcessId = req->ProcessId;
                            g_BlockedApps[g_BlockedAppCount].IsBlocked = TRUE;
                            g_BlockedAppCount++;
                            added = TRUE;
                        }
                        KeReleaseSpinLock(&g_BlockedLock, oldIrql);
                        // Clear connection cache to force re-evaluation
                        if (added) ClearConnCache();
                    }
                    break;

                case IOCTL_FIREWALL_UNBLOCK_APP:
                    if (inputLength >= sizeof(BLOCK_APP_REQUEST)) {
                        PBLOCK_APP_REQUEST req = (PBLOCK_APP_REQUEST)inputBuffer;
                        UNICODE_STRING reqPath, entryPath;
                        BOOLEAN removed = FALSE;
                        RtlInitUnicodeString(&reqPath, req->ApplicationPath);
                        KeAcquireSpinLock(&g_BlockedLock, &oldIrql);
                        for (ULONG i = 0; i < g_BlockedAppCount; i++) {
                            RtlInitUnicodeString(&entryPath, g_BlockedApps[i].ApplicationPath);
                            if (RtlCompareUnicodeString(&reqPath, &entryPath, TRUE) == 0) {
                                if (i < g_BlockedAppCount - 1) {
                                    RtlMoveMemory(&g_BlockedApps[i], &g_BlockedApps[i + 1], (g_BlockedAppCount - i - 1) * sizeof(BLOCKED_APP_ENTRY));
                                }
                                g_BlockedAppCount--;
                                removed = TRUE;
                                break;
                            }
                        }
                        KeReleaseSpinLock(&g_BlockedLock, oldIrql);
                        // Clear connection cache to force re-evaluation
                        if (removed) ClearConnCache();
                    }
                    break;

                case IOCTL_FIREWALL_GET_BLOCKED:
                    if (outputLength >= sizeof(GET_BLOCKED_RESPONSE)) {
                        PGET_BLOCKED_RESPONSE resp = (PGET_BLOCKED_RESPONSE)outputBuffer;
                        KeAcquireSpinLock(&g_BlockedLock, &oldIrql);
                        resp->BlockedCount = g_BlockedAppCount;
                        RtlCopyMemory(resp->Entries, g_BlockedApps, g_BlockedAppCount * sizeof(BLOCKED_APP_ENTRY));
                        KeReleaseSpinLock(&g_BlockedLock, oldIrql);
                        information = sizeof(GET_BLOCKED_RESPONSE);
                    }
                    break;

                case IOCTL_FIREWALL_SET_MONITOR:
                    if (inputLength >= sizeof(SET_MONITOR_REQUEST)) {
                        PSET_MONITOR_REQUEST req = (PSET_MONITOR_REQUEST)inputBuffer;
                        g_MonitoringEnabled = req->EnableMonitoring;
                    }
                    break;

                case IOCTL_FIREWALL_GET_ETW_GUID:
                    if (outputLength >= sizeof(GUID)) {
                        RtlCopyMemory(outputBuffer, &ETW_PROVIDER_GUID, sizeof(GUID));
                        information = sizeof(GUID);
                    }
                    break;

                case IOCTL_FIREWALL_GET_PROCESS_STATS:
                    if (outputLength >= sizeof(GET_PROCESS_STATS_RESPONSE)) {
                        PGET_PROCESS_STATS_RESPONSE resp = (PGET_PROCESS_STATS_RESPONSE)outputBuffer;
                        KeAcquireSpinLock(&g_StatsLock, &oldIrql);
                        resp->Count = g_ProcessStatsCount;
                        RtlCopyMemory(resp->Entries, g_ProcessStats, g_ProcessStatsCount * sizeof(PROCESS_STATS_ENTRY));
                        KeReleaseSpinLock(&g_StatsLock, oldIrql);
                        information = sizeof(GET_PROCESS_STATS_RESPONSE);
                    }
                    break;

                case IOCTL_FIREWALL_RESET_STATS:
                    KeAcquireSpinLock(&g_StatsLock, &oldIrql);
                    RtlZeroMemory(g_ProcessStats, sizeof(g_ProcessStats));
                    g_ProcessStatsCount = 0;
                    KeReleaseSpinLock(&g_StatsLock, oldIrql);
                    InterlockedExchange64(&g_PacketsBlocked, 0);
                    InterlockedExchange64(&g_PacketsAllowed, 0);
                    break;

                case IOCTL_FIREWALL_GET_DEBUG_LOG:
                    if (outputLength >= DRIVER_LOG_SIZE) {
                        KeAcquireSpinLock(&g_LogLock, &oldIrql);
                        RtlCopyMemory(outputBuffer, g_DebugLog, g_LogOffset);
                        information = g_LogOffset;
                        g_LogOffset = 0;
                        RtlZeroMemory(g_DebugLog, DRIVER_LOG_SIZE);
                        KeReleaseSpinLock(&g_LogLock, oldIrql);
                    }
                    break;

                default:
                    status = STATUS_INVALID_DEVICE_REQUEST;
                    break;
            }
            break;

        default:
            status = STATUS_INVALID_DEVICE_REQUEST;
            break;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = information;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
    UNICODE_STRING symbolicLink;

    UnregisterWfpCallouts();
    CleanupEtw();

    RtlInitUnicodeString(&symbolicLink, SYMBOLIC_LINK_NAME);
    IoDeleteSymbolicLink(&symbolicLink);

    if (g_DeviceObject != NULL) {
        IoDeleteDevice(g_DeviceObject);
    }
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    NTSTATUS status;
    UNICODE_STRING deviceName, symbolicLink;

    KeInitializeSpinLock(&g_RulesLock);
    KeInitializeSpinLock(&g_BlockedLock);
    KeInitializeSpinLock(&g_CacheLock);
    KeInitializeSpinLock(&g_StatsLock);
    KeInitializeSpinLock(&g_LogLock);
    RtlZeroMemory(g_ConnCache, sizeof(g_ConnCache));
    RtlZeroMemory(g_ProcessStats, sizeof(g_ProcessStats));
    RtlZeroMemory(g_DebugLog, sizeof(g_DebugLog));

    status = InitializeEtw();
    if (!NT_SUCCESS(status)) return status;

    RtlInitUnicodeString(&deviceName, DEVICE_NAME);
    status = IoCreateDevice(DriverObject, 0, &deviceName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &g_DeviceObject);
    if (!NT_SUCCESS(status)) { CleanupEtw(); return status; }

    RtlInitUnicodeString(&symbolicLink, SYMBOLIC_LINK_NAME);
    status = IoCreateSymbolicLink(&symbolicLink, &deviceName);
    if (!NT_SUCCESS(status)) { IoDeleteDevice(g_DeviceObject); CleanupEtw(); return status; }

    DriverObject->MajorFunction[IRP_MJ_CREATE] = DriverDispatch;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = DriverDispatch;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DriverDispatch;
    DriverObject->DriverUnload = DriverUnload;

    RtlZeroMemory(g_Rules, sizeof(g_Rules));
    RtlZeroMemory(g_BlockedApps, sizeof(g_BlockedApps));

    status = RegisterWfpCallouts();
    if (!NT_SUCCESS(status)) {
        IoDeleteSymbolicLink(&symbolicLink);
        IoDeleteDevice(g_DeviceObject);
        CleanupEtw();
        return status;
    }

    return STATUS_SUCCESS;
}
