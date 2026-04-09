using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.Text;
using Microsoft.Win32;
using HackerFirewall.Infrastructure;
using HackerFirewall.Models;

namespace HackerFirewall.Services
{
    [DataContract]
    public class SessionData
    {
        [DataMember(Name = "version")] public string Version { get; set; } = "2.0";
        [DataMember(Name = "timestamp")] public string TimestampStr { get; set; } = "";
        [DataMember(Name = "blockedApps")] public List<BlockedAppData> BlockedApps { get; set; } = new List<BlockedAppData>();
        [DataMember(Name = "rules")] public List<FirewallRuleData> Rules { get; set; } = new List<FirewallRuleData>();

        public DateTime Timestamp
        {
            get => DateTime.TryParse(TimestampStr, out var dt) ? dt : DateTime.Now;
            set => TimestampStr = value.ToString("o");
        }
    }

    [DataContract]
    public class BlockedAppData
    {
        [DataMember(Name = "path")] public string ApplicationPath { get; set; } = "";
        [DataMember(Name = "name")] public string ApplicationName { get; set; } = "";
        [DataMember(Name = "pid")] public uint ProcessId { get; set; }
    }

    [DataContract]
    public class FirewallRuleData
    {
        [DataMember(Name = "path")] public string ApplicationPath { get; set; } = "";
        [DataMember(Name = "name")] public string ApplicationName { get; set; } = "";
        [DataMember(Name = "pid")] public uint ProcessId { get; set; }
        [DataMember(Name = "action")] public int Action { get; set; }
        [DataMember(Name = "direction")] public int Direction { get; set; } = 2;
        [DataMember(Name = "ports")] public List<PortRangeData> PortRanges { get; set; } = new List<PortRangeData>();
        [DataMember(Name = "ips")] public List<string> IpAddresses { get; set; } = new List<string>();
        [DataMember(Name = "active")] public bool IsActive { get; set; } = true;
    }

    [DataContract]
    public class PortRangeData
    {
        [DataMember(Name = "start")] public ushort StartPort { get; set; }
        [DataMember(Name = "end")] public ushort EndPort { get; set; }
    }

    public class SessionService
    {
        private static readonly DataContractJsonSerializerSettings JsonSettings = new DataContractJsonSerializerSettings
        {
            UseSimpleDictionaryFormat = true
        };

        private static string Serialize(SessionData data)
        {
            var ser = new DataContractJsonSerializer(typeof(SessionData), JsonSettings);
            using (var ms = new MemoryStream())
            {
                ser.WriteObject(ms, data);
                return Encoding.UTF8.GetString(ms.ToArray());
            }
        }

        private static SessionData Deserialize(string json)
        {
            var ser = new DataContractJsonSerializer(typeof(SessionData), JsonSettings);
            using (var ms = new MemoryStream(Encoding.UTF8.GetBytes(json)))
            {
                return (SessionData)ser.ReadObject(ms);
            }
        }

        private static SessionData BuildSessionData(IEnumerable<BlockedApp> blockedApps, IEnumerable<FirewallRule> rules)
        {
            var sessionData = new SessionData { Timestamp = DateTime.Now };

            foreach (var app in blockedApps)
            {
                sessionData.BlockedApps.Add(new BlockedAppData
                {
                    ApplicationPath = app.ApplicationPath,
                    ApplicationName = app.ApplicationName,
                    ProcessId = 0
                });
            }

            foreach (var rule in rules)
            {
                var ruleData = new FirewallRuleData
                {
                    ApplicationPath = rule.ApplicationPath,
                    ApplicationName = rule.ApplicationName,
                    ProcessId = rule.ProcessId,
                    Action = (int)rule.Action,
                    Direction = (int)rule.Direction,
                    IsActive = rule.IsActive
                };

                foreach (var port in rule.PortRanges)
                    ruleData.PortRanges.Add(new PortRangeData { StartPort = port.StartPort, EndPort = port.EndPort });

                foreach (var ip in rule.IpAddresses)
                    ruleData.IpAddresses.Add(ip.ToString());

                sessionData.Rules.Add(ruleData);
            }

            return sessionData;
        }

        public static bool SaveSession(string filePath, IEnumerable<BlockedApp> blockedApps, IEnumerable<FirewallRule> rules)
        {
            try
            {
                var json = Serialize(BuildSessionData(blockedApps, rules));
                File.WriteAllText(filePath, json);
                return true;
            }
            catch (Exception ex)
            {
                LogService.Log($"SessionService: Failed to save - {ex.Message}");
                return false;
            }
        }

        public static SessionData LoadSession(string filePath)
        {
            try
            {
                if (!File.Exists(filePath)) return null;
                var json = File.ReadAllText(filePath);
                var data = Deserialize(json);
                LogService.Log($"SessionService: Loaded from {data.Timestamp:yyyy-MM-dd HH:mm:ss}");
                return data;
            }
            catch (Exception ex)
            {
                LogService.Log($"SessionService: Failed to load - {ex.Message}");
                return null;
            }
        }

        public static BlockedApp ToBlockedApp(BlockedAppData data)
        {
            return new BlockedApp
            {
                ApplicationPath = data.ApplicationPath,
                ApplicationName = data.ApplicationName,
                ProcessId = 0,
                IsBlocked = true
            };
        }

        public static FirewallRule ToFirewallRule(FirewallRuleData data)
        {
            var rule = new FirewallRule
            {
                ApplicationPath = data.ApplicationPath,
                ApplicationName = data.ApplicationName,
                ProcessId = data.ProcessId,
                Action = (FirewallAction)data.Action,
                Direction = (TrafficDirection)data.Direction,
                IsActive = data.IsActive
            };

            foreach (var port in data.PortRanges)
                rule.PortRanges.Add(new PortRange { StartPort = port.StartPort, EndPort = port.EndPort });

            foreach (var ipStr in data.IpAddresses)
            {
                try { rule.IpAddresses.Add(IpAddressEntry.FromString(ipStr)); }
                catch (Exception ex) { LogService.Log($"SessionService: IP parse error '{ipStr}' - {ex.Message}"); }
            }

            return rule;
        }

        // ═══════════════════════════════════════════
        // Registry persistence
        // ═══════════════════════════════════════════

        private const string RegistryKey = @"SOFTWARE\WireFirewall";

        public static bool SaveToRegistry(IEnumerable<BlockedApp> blockedApps, IEnumerable<FirewallRule> rules)
        {
            try
            {
                var sessionData = BuildSessionData(blockedApps, rules);
                var json = Serialize(sessionData);

                using (var key = Registry.LocalMachine.CreateSubKey(RegistryKey))
                {
                    key.SetValue("Session", json, RegistryValueKind.String);
                }

                LogService.Log($"Registry: Saved {sessionData.BlockedApps.Count} blocked, {sessionData.Rules.Count} rules");
                return true;
            }
            catch (Exception ex)
            {
                LogService.Log($"Registry: Failed to save - {ex.Message}");
                return false;
            }
        }

        public static SessionData LoadFromRegistry()
        {
            try
            {
                using (var key = Registry.LocalMachine.OpenSubKey(RegistryKey))
                {
                    if (key == null) return null;
                    var json = key.GetValue("Session") as string;
                    if (string.IsNullOrEmpty(json)) return null;

                    var data = Deserialize(json);
                    LogService.Log($"Registry: Loaded {data.BlockedApps.Count} blocked, {data.Rules.Count} rules");
                    return data;
                }
            }
            catch (Exception ex)
            {
                LogService.Log($"Registry: Failed to load - {ex.Message}");
                return null;
            }
        }
    }
}
