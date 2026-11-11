// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Collections.Generic;
using Tum.Trust.Security.Core.Models.Logging;
using Tum.Trust.Security.Core.Models.Sigma;
using Tum.Trust.Security.Infrastructure.Sigma;
using Xunit;

namespace Tum.Trust.Security.Tests
{
    public class SigmaRuleEngineTests
    {
        [Fact]
        public void SigmaRuleParser_ParsesValidYamlCorrectly()
        {
            string yaml = @"
title: Suspicious PowerShell Download Cradle
id: 3b1451f2-70b9-4677-83c3-d021c33f2bcf
status: test
description: Detects suspicious PowerShell cradle downloading code from remote host
level: high
tags:
    - attack.execution
    - attack.t1059.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        EventName: 'PROCESS.CREATE'
        PayloadSanitized|contains:
            - 'DownloadString'
            - 'Invoke-WebRequest'
    filter:
        UserId: 'svc_deployment'
    condition: selection and not filter
";

            var rule = SigmaRuleParser.ParseYaml(yaml);

            Assert.Equal("Suspicious PowerShell Download Cradle", rule.Title);
            Assert.Equal("3b1451f2-70b9-4677-83c3-d021c33f2bcf", rule.Id);
            Assert.Equal(SigmaRuleLevel.High, rule.Level);
            Assert.Equal("process_creation", rule.LogSource.Category);
            Assert.Equal("windows", rule.LogSource.Product);
            Assert.Contains("attack.execution", rule.Tags);
            Assert.Contains("T1059.001", rule.GetMitreTechniques());
            Assert.True(rule.Selections.ContainsKey("selection"));
            Assert.True(rule.Selections.ContainsKey("filter"));
            Assert.Equal("selection and not filter", rule.Condition);
        }

        [Fact]
        public void SigmaRuleEngine_EvaluatesCompiledExpressionTrees()
        {
            var engine = new SigmaRuleEngine();

            var rule = new SigmaRule
            {
                Id = "rule-sql-injection-001",
                Title = "Potential SQL Injection Detected",
                Level = SigmaRuleLevel.Critical,
                Tags = new List<string> { "attack.t1190" },
                Selections = new Dictionary<string, Dictionary<string, List<string>>>
                {
                    ["selection"] = new Dictionary<string, List<string>>
                    {
                        ["EventName"] = new List<string> { "HTTP.REQUEST" },
                        ["PayloadSanitized|contains"] = new List<string> { "UNION SELECT", "OR 1=1" }
                    },
                    ["filter"] = new Dictionary<string, List<string>>
                    {
                        ["ClientIp"] = new List<string> { "127.0.0.1" }
                    }
                },
                Condition = "selection and not filter"
            };

            engine.RegisterRule(rule);
            Assert.Equal(1, engine.ActiveRuleCount);

            // Test 1: Attack from external IP -> MATCH
            var maliciousEntry = new TumLogEntry
            {
                LogId = "log-malicious",
                EventName = "HTTP.REQUEST",
                ClientIp = "203.0.113.55",
                PayloadSanitized = "GET /api/users?id=1 UNION SELECT null, username, password FROM users--"
            };

            var matches = engine.Evaluate(maliciousEntry);
            Assert.Single(matches);
            Assert.Equal("rule-sql-injection-001", matches[0].RuleId);
            Assert.Equal(SigmaRuleLevel.Critical, matches[0].Level);
            Assert.Contains("T1190", matches[0].MitreTechniques);

            // Test 2: Attack from local loopback (filtered out) -> NO MATCH
            var filteredEntry = new TumLogEntry
            {
                LogId = "log-filtered",
                EventName = "HTTP.REQUEST",
                ClientIp = "127.0.0.1",
                PayloadSanitized = "GET /api/users?id=1 UNION SELECT null, username, password FROM users--"
            };

            var filteredMatches = engine.Evaluate(filteredEntry);
            Assert.Empty(filteredMatches);

            // Test 3: Normal benign traffic -> NO MATCH
            var benignEntry = new TumLogEntry
            {
                LogId = "log-benign",
                EventName = "HTTP.REQUEST",
                ClientIp = "203.0.113.55",
                PayloadSanitized = "GET /api/users?id=42"
            };

            var benignMatches = engine.Evaluate(benignEntry);
            Assert.Empty(benignMatches);
        }

        [Fact]
        public void SigmaRuleEngine_SupportsStartsWithAndEndsWithModifiers()
        {
            var engine = new SigmaRuleEngine();

            var rule = new SigmaRule
            {
                Id = "rule-path-traversal-002",
                Title = "Web Path Traversal Probe",
                Level = SigmaRuleLevel.High,
                Selections = new Dictionary<string, Dictionary<string, List<string>>>
                {
                    ["selection"] = new Dictionary<string, List<string>>
                    {
                        ["RequestPath|startswith"] = new List<string> { "/etc/", "/var/log" },
                        ["RequestPath|endswith"] = new List<string> { "passwd", "shadow" }
                    }
                },
                Condition = "selection"
            };

            engine.RegisterRule(rule);

            var probe = new TumLogEntry
            {
                RequestPath = "/etc/security/passwd"
            };

            var matches = engine.Evaluate(probe);
            Assert.Single(matches);
            Assert.Equal("rule-path-traversal-002", matches[0].RuleId);
        }

        [Fact]
        public void SigmaRuleEngine_InvertedIndexing_PartitionsRulesAndGuardsAgainstEvasion()
        {
            var engine = new SigmaRuleEngine();

            // 1. Register 30 dummy process_creation rules
            for (int i = 1; i <= 30; i++)
            {
                engine.RegisterRule(new SigmaRule
                {
                    Id = $"rule-process-{i:D3}",
                    Title = $"Suspicious Process Execution {i}",
                    Level = SigmaRuleLevel.Medium,
                    LogSource = new SigmaLogSource { Category = "process_creation" },
                    Selections = new Dictionary<string, Dictionary<string, List<string>>>
                    {
                        ["selection"] = new Dictionary<string, List<string>>
                        {
                            ["PayloadSanitized|contains"] = new List<string> { $"malicious_proc_{i}.exe" }
                        }
                    },
                    Condition = "selection"
                });
            }

            // 2. Register 1 specific process execution rule detecting cmd.exe
            engine.RegisterRule(new SigmaRule
            {
                Id = "rule-proc-cmd-exec",
                Title = "Windows Command Shell Execution",
                Level = SigmaRuleLevel.High,
                LogSource = new SigmaLogSource { Category = "process_creation" },
                Selections = new Dictionary<string, Dictionary<string, List<string>>>
                {
                    ["selection"] = new Dictionary<string, List<string>>
                    {
                        ["PayloadSanitized|contains"] = new List<string> { "cmd.exe" }
                    }
                },
                Condition = "selection"
            });

            // 3. Register 1 webserver rule
            engine.RegisterRule(new SigmaRule
            {
                Id = "rule-web-sqli-001",
                Title = "Web SQL Injection",
                Level = SigmaRuleLevel.Critical,
                LogSource = new SigmaLogSource { Category = "webserver" },
                Selections = new Dictionary<string, Dictionary<string, List<string>>>
                {
                    ["selection"] = new Dictionary<string, List<string>>
                    {
                        ["PayloadSanitized|contains"] = new List<string> { "UNION SELECT" }
                    }
                },
                Condition = "selection"
            });

            Assert.Equal(32, engine.ActiveRuleCount);

            // Case A: Web traffic with SQLi -> correctly matches web rule via inverted index
            var webEntry = new TumLogEntry
            {
                RequestPath = "/api/v1/search",
                HttpMethod = "GET",
                PayloadSanitized = "GET /api/v1/search?q=1 UNION SELECT 1,2,3"
            };
            var webMatches = engine.Evaluate(webEntry);
            Assert.Single(webMatches);
            Assert.Equal("rule-web-sqli-001", webMatches[0].RuleId);

            // Case B: Evasive Log: Attacker sets Category to AuditTrail and EventName to benign,
            // but payload contains disguised 'cmd.exe' command injection -> caught by Anti-Bypass Guard
            var evasiveEntry = new TumLogEntry
            {
                Category = LogCategory.AuditTrail,
                EventName = "System.HealthCheck",
                PayloadSanitized = "PING status=ok; cmd.exe /c whoami"
            };
            var evasiveMatches = engine.Evaluate(evasiveEntry);
            Assert.Single(evasiveMatches);
            Assert.Equal("rule-proc-cmd-exec", evasiveMatches[0].RuleId);

            // Case C: Completely benign audit log -> 0 matches
            var benignEntry = new TumLogEntry
            {
                Category = LogCategory.AuditTrail,
                EventName = "User.ProfileUpdate",
                PayloadSanitized = "User updated profile photo successfully."
            };
            var benignMatches = engine.Evaluate(benignEntry);
            Assert.Empty(benignMatches);
        }
    }
}
