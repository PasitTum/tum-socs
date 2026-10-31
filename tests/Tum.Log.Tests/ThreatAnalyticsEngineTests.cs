// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Tum.Trust.Security.Core.Models.Logging;
using Tum.Trust.Security.Core.Models.Sigma;
using Tum.Trust.Security.Infrastructure.Analytics;
using Tum.Trust.Security.Infrastructure.Logging;
using Tum.Trust.Security.Infrastructure.Sigma;
using Xunit;

namespace Tum.Trust.Security.Tests
{
    public class ThreatAnalyticsEngineTests
    {
        [Fact]
        public async Task ThreatAnalyticsEngine_GeneratesDashboardSummary_AndAttackGraph()
        {
            var options = new TumLogOptions { StorageDirectory = "./test_storage_analytics_" + Guid.NewGuid().ToString("N") };
            var storage = new TamperProofLogChain(options);
            var sigma = new SigmaRuleEngine();

            var analytics = new ThreatAnalyticsEngine(storage, sigma, null, options);

            // Record events
            var threatEntry = new TumLogEntry
            {
                LogId = "threat-001",
                Category = LogCategory.SecurityThreat,
                ClientIp = "203.0.113.88",
                RequestPath = "/admin/sql_query",
                PiiRedactedCount = 2,
                EventName = "HTTP.EXPLOIT"
            };

            var sigmaMatches = new List<SigmaMatchResult>
            {
                new SigmaMatchResult
                {
                    RuleId = "sigma-sqli",
                    RuleTitle = "SQL Injection in Admin Portal",
                    Level = SigmaRuleLevel.Critical,
                    MitreTechniques = new List<string> { "T1190" }
                }
            };

            analytics.RecordEvent(threatEntry, sigmaMatches);

            // Verify Dashboard Summary
            var summary = analytics.GetDashboardSummary();
            Assert.Equal(1, summary.TotalEventsIngested);
            Assert.Equal(1, summary.CriticalAlertsCount);
            Assert.Equal(2, summary.TotalPiiRedacted);
            Assert.True(summary.TopAttackerIps.ContainsKey("203.0.113.88"));
            Assert.True(summary.TopAttackedEndpoints.ContainsKey("/admin/sql_query"));
            Assert.True(summary.MitreTechniquesSummary.ContainsKey("T1190"));

            // Verify Attack Graph
            var graph = analytics.GetAttackGraph(50);
            Assert.NotEmpty(graph.Nodes);
            Assert.NotEmpty(graph.Edges);
            Assert.Contains(graph.Nodes, n => n.Label == "203.0.113.88" && n.Type == "AttackerIp");
            Assert.Contains(graph.Nodes, n => n.Label == "/admin/sql_query" && n.Type == "TargetAsset");
            Assert.Contains(graph.Nodes, n => n.Label == "T1190" && n.Type == "MitreTechnique");
            Assert.Contains(graph.Edges, e => e.Relation == "Attacks");
            Assert.Contains(graph.Edges, e => e.Relation == "Leverages");

            // Verify Compliance Audit
            var audit = await analytics.GenerateComplianceAuditAsync();
            Assert.True(audit.ComputerCrimeActSec26Compliant);
            Assert.True(audit.ThaiPdpaCompliant);
            Assert.True(audit.Iso27001Compliant);
            Assert.Equal("TUM-TRUST-SECURITY-COMPLIANCE-CCA2560-SEC26", audit.CertificationId);
        }
    }
}
