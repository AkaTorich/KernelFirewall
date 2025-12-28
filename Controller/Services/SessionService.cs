using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;
using FirewallController.Models;

namespace FirewallController.Services
{
    /// <summary>
    /// Data model for session persistence
    /// </summary>
    public class SessionData
    {
        [JsonPropertyName("version")]
        public string Version { get; set; } = "2.0";

        [JsonPropertyName("timestamp")]
        public DateTime Timestamp { get; set; } = DateTime.Now;

        [JsonPropertyName("blockedApps")]
        public List<BlockedAppData> BlockedApps { get; set; } = new();

        [JsonPropertyName("rules")]
        public List<FirewallRuleData> Rules { get; set; } = new();
    }

    /// <summary>
    /// Blocked application data (from block list)
    /// Note: PID is always saved as 0 to enable blocking by application name/path
    /// instead of specific process instance. After restart, all processes with
    /// matching path will be automatically blocked.
    /// </summary>
    public class BlockedAppData
    {
        [JsonPropertyName("path")]
        public string ApplicationPath { get; set; } = "";

        [JsonPropertyName("name")]
        public string ApplicationName { get; set; } = "";

        [JsonPropertyName("pid")]
        public uint ProcessId { get; set; }
    }

    /// <summary>
    /// Firewall rule data (from filtering rules)
    /// Note: PID is preserved as-is. Rules with PID > 0 will match specific process instance,
    /// rules with PID = 0 will match by application path.
    /// </summary>
    public class FirewallRuleData
    {
        [JsonPropertyName("path")]
        public string ApplicationPath { get; set; } = "";

        [JsonPropertyName("name")]
        public string ApplicationName { get; set; } = "";

        [JsonPropertyName("pid")]
        public uint ProcessId { get; set; }

        [JsonPropertyName("action")]
        public FirewallAction Action { get; set; }

        [JsonPropertyName("direction")]
        public TrafficDirection Direction { get; set; } = TrafficDirection.Output;

        [JsonPropertyName("ports")]
        public List<PortRangeData> PortRanges { get; set; } = new();

        [JsonPropertyName("ips")]
        public List<string> IpAddresses { get; set; } = new();

        [JsonPropertyName("active")]
        public bool IsActive { get; set; } = true;
    }

    public class PortRangeData
    {
        [JsonPropertyName("start")]
        public ushort StartPort { get; set; }

        [JsonPropertyName("end")]
        public ushort EndPort { get; set; }
    }

    /// <summary>
    /// Service for saving and loading firewall sessions
    /// </summary>
    public class SessionService
    {
        private static readonly JsonSerializerOptions JsonOptions = new()
        {
            WriteIndented = true,
            PropertyNameCaseInsensitive = true,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
        };

        /// <summary>
        /// Save current session to file
        /// </summary>
        public static bool SaveSession(string filePath,
                                       IEnumerable<BlockedApp> blockedApps,
                                       IEnumerable<FirewallRule> rules)
        {
            try
            {
                var sessionData = new SessionData
                {
                    Timestamp = DateTime.Now
                };

                // Convert blocked apps (PID is set to 0 to block by name/path, not by specific process)
                foreach (var app in blockedApps)
                {
                    sessionData.BlockedApps.Add(new BlockedAppData
                    {
                        ApplicationPath = app.ApplicationPath,
                        ApplicationName = app.ApplicationName,
                        ProcessId = 0  // Always 0 - block by application path, not by PID
                    });
                }

                // Convert rules
                foreach (var rule in rules)
                {
                    var ruleData = new FirewallRuleData
                    {
                        ApplicationPath = rule.ApplicationPath,
                        ApplicationName = rule.ApplicationName,
                        ProcessId = rule.ProcessId,
                        Action = rule.Action,
                        Direction = rule.Direction,
                        IsActive = rule.IsActive
                    };

                    // Convert port ranges
                    foreach (var port in rule.PortRanges)
                    {
                        ruleData.PortRanges.Add(new PortRangeData
                        {
                            StartPort = port.StartPort,
                            EndPort = port.EndPort
                        });
                    }

                    // Convert IP addresses to string representation
                    foreach (var ip in rule.IpAddresses)
                    {
                        ruleData.IpAddresses.Add(ip.ToString());
                    }

                    sessionData.Rules.Add(ruleData);
                }

                // Serialize and save
                var json = JsonSerializer.Serialize(sessionData, JsonOptions);
                File.WriteAllText(filePath, json);
                return true;
            }
            catch (Exception ex)
            {
                LogWindow.Log($"SessionService: Failed to save - {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Load session from file
        /// </summary>
        public static SessionData? LoadSession(string filePath)
        {
            try
            {
                if (!File.Exists(filePath))
                {
                    LogWindow.Log($"SessionService: File not found - {filePath}");
                    return null;
                }

                var json = File.ReadAllText(filePath);
                var sessionData = JsonSerializer.Deserialize<SessionData>(json, JsonOptions);

                if (sessionData == null)
                {
                    LogWindow.Log("SessionService: Failed to deserialize session data");
                    return null;
                }

                LogWindow.Log($"SessionService: Loaded session from {sessionData.Timestamp:yyyy-MM-dd HH:mm:ss}");
                LogWindow.Log($"SessionService: {sessionData.BlockedApps.Count} blocked apps (will block by name/path), {sessionData.Rules.Count} rules");
                return sessionData;
            }
            catch (Exception ex)
            {
                LogWindow.Log($"SessionService: Failed to load - {ex.Message}");
                return null;
            }
        }

        /// <summary>
        /// Convert loaded data back to BlockedApp model
        /// </summary>
        public static BlockedApp ToBlockedApp(BlockedAppData data)
        {
            return new BlockedApp
            {
                ApplicationPath = data.ApplicationPath,
                ApplicationName = data.ApplicationName,
                ProcessId = 0,  // Always 0 - will block by application path, not by PID
                IsBlocked = true
            };
        }

        /// <summary>
        /// Convert loaded data back to FirewallRule model
        /// </summary>
        public static FirewallRule ToFirewallRule(FirewallRuleData data)
        {
            var rule = new FirewallRule
            {
                ApplicationPath = data.ApplicationPath,
                ApplicationName = data.ApplicationName,
                ProcessId = data.ProcessId,
                Action = data.Action,
                Direction = data.Direction,
                IsActive = data.IsActive
            };

            // Convert port ranges
            foreach (var port in data.PortRanges)
            {
                rule.PortRanges.Add(new PortRange
                {
                    StartPort = port.StartPort,
                    EndPort = port.EndPort
                });
            }

            // Convert IP addresses from string
            foreach (var ipStr in data.IpAddresses)
            {
                try
                {
                    rule.IpAddresses.Add(IpAddressEntry.FromString(ipStr));
                }
                catch (Exception ex)
                {
                    LogWindow.Log($"SessionService: Failed to parse IP '{ipStr}' - {ex.Message}");
                }
            }

            return rule;
        }
    }
}
