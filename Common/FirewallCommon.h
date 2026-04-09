#pragma once

#include <guiddef.h>

// Device names
#define DEVICE_NAME         L"\\Device\\KernelFirewall"
#define SYMBOLIC_LINK_NAME  L"\\DosDevices\\KernelFirewall"
#define USER_DEVICE_PATH    L"\\\\.\\KernelFirewall"

// IOCTL codes
#define FIREWALL_IOCTL_BASE 0x8000

#define IOCTL_FIREWALL_ADD_RULE         CTL_CODE(FIREWALL_IOCTL_BASE, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_FIREWALL_REMOVE_RULE      CTL_CODE(FIREWALL_IOCTL_BASE, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_FIREWALL_CLEAR_RULES      CTL_CODE(FIREWALL_IOCTL_BASE, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_FIREWALL_GET_RULES        CTL_CODE(FIREWALL_IOCTL_BASE, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_FIREWALL_ENABLE           CTL_CODE(FIREWALL_IOCTL_BASE, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_FIREWALL_DISABLE          CTL_CODE(FIREWALL_IOCTL_BASE, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_FIREWALL_GET_STATUS       CTL_CODE(FIREWALL_IOCTL_BASE, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_FIREWALL_BLOCK_APP        CTL_CODE(FIREWALL_IOCTL_BASE, 0x807, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_FIREWALL_UNBLOCK_APP      CTL_CODE(FIREWALL_IOCTL_BASE, 0x808, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_FIREWALL_GET_BLOCKED      CTL_CODE(FIREWALL_IOCTL_BASE, 0x809, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_FIREWALL_SET_MONITOR      CTL_CODE(FIREWALL_IOCTL_BASE, 0x80C, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_FIREWALL_GET_ETW_GUID     CTL_CODE(FIREWALL_IOCTL_BASE, 0x80D, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_FIREWALL_GET_PROCESS_STATS CTL_CODE(FIREWALL_IOCTL_BASE, 0x80E, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_FIREWALL_RESET_STATS      CTL_CODE(FIREWALL_IOCTL_BASE, 0x80F, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_FIREWALL_GET_DEBUG_LOG    CTL_CODE(FIREWALL_IOCTL_BASE, 0x810, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define DRIVER_LOG_SIZE 8192

// Maximum constants
#define MAX_PATH_LENGTH         520
#define MAX_PROCESS_NAME        128
#define MAX_IP_ADDRESSES        64
#define MAX_PORT_RANGES         32
#define MAX_RULES               256
#define MAX_BLOCKED_APPS        512

// Address family constants (matching Windows AF_ values)
#define ADDRESS_FAMILY_IPV4     2      // AF_INET
#define ADDRESS_FAMILY_IPV6     23     // AF_INET6

// ETW Event IDs
#define ETW_EVENT_ID_NETWORK    1
#define ETW_EVENT_ID_BLOCKED    2
#define ETW_EVENT_ID_ALLOWED    3

// ETW Keywords
#define ETW_KEYWORD_NETWORK     0x1
#define ETW_KEYWORD_BLOCK       0x2
#define ETW_KEYWORD_ALLOW       0x4

// Rule action
typedef enum _FIREWALL_ACTION {
    FirewallActionBlock = 0,
    FirewallActionAllow = 1,
    FirewallActionAllowRestricted = 2
} FIREWALL_ACTION;

// Traffic direction filter
typedef enum _TRAFFIC_DIRECTION {
    TrafficDirectionAny = 0,      // Match any direction (input + output)
    TrafficDirectionInput = 1,    // Match incoming traffic (remote -> local)
    TrafficDirectionOutput = 2    // Match outgoing traffic (local -> remote)
} TRAFFIC_DIRECTION;

// Port range structure
typedef struct _PORT_RANGE {
    USHORT StartPort;
    USHORT EndPort;
} PORT_RANGE, *PPORT_RANGE;

// IP address entry (supports both IPv4 and IPv6)
typedef struct _IP_ADDRESS_ENTRY {
    USHORT AddressFamily;     // ADDRESS_FAMILY_IPV4 or ADDRESS_FAMILY_IPV6
    USHORT Reserved;          // Padding for alignment
    union {
        // IPv4 address structure
        struct {
            ULONG Address;    // 32-bit IPv4 address
            ULONG Mask;       // Subnet mask
            UCHAR _Padding[24]; // Pad to match IPv6 size
        } V4;
        // IPv6 address structure
        struct {
            UCHAR Address[16]; // 128-bit IPv6 address
            UCHAR PrefixLength; // IPv6 prefix length (0-128)
            UCHAR _Padding[15]; // Reserved for future use
        } V6;
    };
} IP_ADDRESS_ENTRY, *PIP_ADDRESS_ENTRY;

// Compile-time size assertion (48 bytes total)
#ifndef _KERNEL_MODE
static_assert(sizeof(IP_ADDRESS_ENTRY) == 48, "IP_ADDRESS_ENTRY size must be 48 bytes");
#endif

// Firewall rule structure
typedef struct _FIREWALL_RULE {
    ULONG RuleId;
    WCHAR ApplicationPath[MAX_PATH_LENGTH];
    ULONG ProcessId;  // 0 = match by path, non-zero = match by PID
    FIREWALL_ACTION Action;
    TRAFFIC_DIRECTION Direction;  // Which side IP/ports apply to (Any/Source/Destination)

    ULONG PortRangeCount;
    PORT_RANGE PortRanges[MAX_PORT_RANGES];

    ULONG IpAddressCount;
    IP_ADDRESS_ENTRY IpAddresses[MAX_IP_ADDRESSES];

    BOOLEAN IsActive;
} FIREWALL_RULE, *PFIREWALL_RULE;

// Simple block entry for mass blocking
typedef struct _BLOCKED_APP_ENTRY {
    WCHAR ApplicationPath[MAX_PATH_LENGTH];
    ULONG ProcessId;
    BOOLEAN IsBlocked;
} BLOCKED_APP_ENTRY, *PBLOCKED_APP_ENTRY;

// Firewall status
typedef struct _FIREWALL_STATUS {
    BOOLEAN IsEnabled;
    ULONG RuleCount;
    ULONG BlockedAppCount;
    ULONG PacketsBlocked;
    ULONG PacketsAllowed;
} FIREWALL_STATUS, *PFIREWALL_STATUS;

// Request structures for IOCTLs
typedef struct _ADD_RULE_REQUEST {
    FIREWALL_RULE Rule;
} ADD_RULE_REQUEST, *PADD_RULE_REQUEST;

typedef struct _REMOVE_RULE_REQUEST {
    ULONG RuleId;
} REMOVE_RULE_REQUEST, *PREMOVE_RULE_REQUEST;

typedef struct _BLOCK_APP_REQUEST {
    WCHAR ApplicationPath[MAX_PATH_LENGTH];
    ULONG ProcessId;
} BLOCK_APP_REQUEST, *PBLOCK_APP_REQUEST;

// Response structures
typedef struct _GET_RULES_RESPONSE {
    ULONG RuleCount;
    FIREWALL_RULE Rules[MAX_RULES];
} GET_RULES_RESPONSE, *PGET_RULES_RESPONSE;

typedef struct _GET_BLOCKED_RESPONSE {
    ULONG BlockedCount;
    BLOCKED_APP_ENTRY Entries[MAX_BLOCKED_APPS];
} GET_BLOCKED_RESPONSE, *PGET_BLOCKED_RESPONSE;

// Monitor control request
typedef struct _SET_MONITOR_REQUEST {
    BOOLEAN EnableMonitoring;
} SET_MONITOR_REQUEST, *PSET_MONITOR_REQUEST;

// ETW Network Event structure - matches driver's ETW_EVENT_DATA
#define ETW_MAX_PACKET_DATA 12800

#pragma pack(push, 1)
typedef struct _ETW_EVENT_HEADER {
    ULONG64 Timestamp;
    ULONG ProcessId;
    CHAR ProcessName[64];  // Increased from 16 to support long process names
    USHORT AddressFamily;  // ADDRESS_FAMILY_IPV4 or ADDRESS_FAMILY_IPV6
    USHORT Reserved1;      // Padding for alignment
    // Unified address fields (union for IPv4/IPv6)
    union {
        // IPv4 addresses
        struct {
            ULONG LocalIp;
            ULONG RemoteIp;
            UCHAR _Padding[24]; // Pad to match IPv6 size
        } V4;
        // IPv6 addresses
        struct {
            UCHAR LocalIp[16];
            UCHAR RemoteIp[16];
        } V6;
    };
    USHORT LocalPort;
    USHORT RemotePort;
    UCHAR Protocol;
    UCHAR Direction;
    UCHAR WasBlocked;
    UCHAR Reserved2;
    USHORT DataSize;
} ETW_EVENT_HEADER, *PETW_EVENT_HEADER;

typedef struct _ETW_NETWORK_EVENT {
    ETW_EVENT_HEADER Header;
    UCHAR PacketData[ETW_MAX_PACKET_DATA];
} ETW_NETWORK_EVENT, *PETW_NETWORK_EVENT;
#pragma pack(pop)

// Protocol type
typedef enum _PROTOCOL_TYPE {
    ProtocolTCP = 6,
    ProtocolUDP = 17,
    ProtocolOther = 0
} PROTOCOL_TYPE;

// Per-process traffic statistics
#define MAX_PROCESS_STATS 256

typedef struct _PROCESS_STATS_ENTRY {
    CHAR ProcessName[64];      // Process name (ASCII)
    ULONG PacketsSent;         // Outbound packets
    ULONG PacketsRecv;         // Inbound packets
    ULONG PacketsBlocked;      // Blocked packets
    ULONG BytesSent;           // Outbound bytes
    ULONG BytesRecv;           // Inbound bytes
} PROCESS_STATS_ENTRY, *PPROCESS_STATS_ENTRY;

typedef struct _GET_PROCESS_STATS_RESPONSE {
    ULONG Count;
    PROCESS_STATS_ENTRY Entries[MAX_PROCESS_STATS];
} GET_PROCESS_STATS_RESPONSE, *PGET_PROCESS_STATS_RESPONSE;
