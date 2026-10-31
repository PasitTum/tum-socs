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
    }
}
