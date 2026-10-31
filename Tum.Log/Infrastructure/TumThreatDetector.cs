// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using Tum.Trust.Security.Core.Interfaces.Logging;
using Tum.Trust.Security.Core.Models.Logging;

namespace Tum.Trust.Security.Infrastructure.Logging
{
    /// <summary>
    /// Heuristic and signature-based threat detection engine inspecting web requests and payloads in real time.
    /// Protects against OWASP Top 10 vectors (SQLi, XSS, Path Traversal, OS Command Injection).
    /// </summary>
    public class TumThreatDetector : ITumThreatDetector
    {
        private static readonly (ThreatType Type, string Severity, Regex Pattern, string Description)[] ThreatRules =
        {
            // SQL Injection
            (ThreatType.SqlInjection, "Critical",
             new Regex(@"(?i)\b(union\s+select|select\s+.+\s+from|insert\s+into|delete\s+from|drop\s+table|update\s+.+\s+set)\b", RegexOptions.Compiled),
             "Classic SQL DDL/DML injection keywords detected"),

            (ThreatType.SqlInjection, "High",
             new Regex(@"(?i)(?:'|\%27)\s*(?:or|and)\s*[\w\d]+(?:\s*=\s*[\w\d]+|--|#)", RegexOptions.Compiled),
             "SQL boolean condition bypass (' OR 1=1 / ' OR 'a'='a') detected"),

            (ThreatType.SqlInjection, "Critical",
             new Regex(@"(?i)\bexec(?:\s+|\+)+(?:xp_cmdshell|sp_executesql)\b", RegexOptions.Compiled),
             "Database stored procedure execution injection detected"),

            // Cross-Site Scripting (XSS)
            (ThreatType.CrossSiteScripting, "High",
             new Regex(@"(?i)<\s*script[^>]*>[\s\S]*?<\s*/\s*script\s*>", RegexOptions.Compiled),
             "Explicit HTML script tag injection detected"),

            (ThreatType.CrossSiteScripting, "High",
             new Regex(@"(?i)(?:javascript\s*:|vbscript\s*:|data\s*:text/html)", RegexOptions.Compiled),
             "JavaScript URI pseudo-protocol execution attempt"),

            (ThreatType.CrossSiteScripting, "Medium",
             new Regex(@"(?i)\bon(?:error|load|click|mouseover|focus|blur)\s*=", RegexOptions.Compiled),
             "Inline DOM event-handler injection detected"),

            // Path Traversal
            (ThreatType.PathTraversal, "High",
             new Regex(@"(?:\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|\.\.%2f)", RegexOptions.Compiled),
             "Directory traversal relative path escape sequence (../ or ..\\) detected"),

            (ThreatType.PathTraversal, "Critical",
             new Regex(@"(?i)(?:/etc/(?:passwd|shadow|hosts)|(?:c:|d:)[\\/](?:windows|winnt)[\\/](?:system32|win\.ini))", RegexOptions.Compiled),
             "Targeted access attempt against sensitive OS system files detected"),

            // Command Injection
            (ThreatType.CommandInjection, "Critical",
             new Regex(@"(?i)(?:;|\||`|\$\()\s*(?:cat|ls|rm|chmod|whoami|curl|wget|powershell|cmd\.exe|nc|netcat)\b", RegexOptions.Compiled),
             "Operating system shell command chaining injection detected")
        };

        /// <inheritdoc />
        public List<SecurityThreatAlert> InspectPayload(string payload, string sourceIp = "127.0.0.1")
        {
            var alerts = new List<SecurityThreatAlert>();
            if (string.IsNullOrWhiteSpace(payload))
            {
                return alerts;
            }

            foreach (var (type, severity, regex, desc) in ThreatRules)
            {
                var match = regex.Match(payload);
                if (match.Success)
                {
                    alerts.Add(new SecurityThreatAlert
                    {
                        ThreatType = type,
                        Severity = severity,
                        MatchedPattern = desc,
                        SuspiciousSnippet = match.Value.Length > 80 ? match.Value.Substring(0, 80) + "..." : match.Value,
                        MitigationAction = "SanitizedAndAudited",
                        SourceIp = sourceIp,
                        TimestampUtc = DateTimeOffset.UtcNow
                    });
                }
            }

            return alerts;
        }

        /// <inheritdoc />
        public List<SecurityThreatAlert> InspectRequest(string? path, string? method, string? queryString, string? body, string sourceIp = "127.0.0.1")
        {
            var aggregated = new List<SecurityThreatAlert>();

            if (!string.IsNullOrEmpty(path))
            {
                aggregated.AddRange(InspectPayload(path, sourceIp));
            }

            if (!string.IsNullOrEmpty(queryString))
            {
                aggregated.AddRange(InspectPayload(queryString, sourceIp));
            }

            if (!string.IsNullOrEmpty(body))
            {
                aggregated.AddRange(InspectPayload(body, sourceIp));
            }

            return aggregated;
        }
    }
}
