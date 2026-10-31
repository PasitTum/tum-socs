// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Tum.Trust.Security.Core.Models.Alerts;
using Tum.Trust.Security.Core.Models.Logging;
using Tum.Trust.Security.Core.Models.Query;
using Tum.Trust.Security.Core.Models.Risk;
using Tum.Trust.Security.Core.Models.Sigma;
using Tum.Trust.Security.Infrastructure.Alerts;
using Tum.Trust.Security.Infrastructure.Analytics;
using Tum.Trust.Security.Infrastructure.Ingestion;
using Tum.Trust.Security.Infrastructure.Logging;
using Tum.Trust.Security.Infrastructure.Query;
using Tum.Trust.Security.Infrastructure.Risk;
using Tum.Trust.Security.Infrastructure.Sigma;
using Xunit;

namespace Tum.Trust.Security.Tests
{
    public class TumOpenSiemEndToEndTests
    {
        [Fact]
        public async Task OpenSiem_EndToEnd_Ingestion_Sigma_Risk_Query_And_Compliance_Workflow()
        {
            string testDir = Path.Combine(Path.GetTempPath(), "siem_e2e_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(testDir);

            try
            {
                // 1. Initialize SIEM Subsystems
                var options = new TumLogOptions
                {
                    StorageDirectory = testDir,
                    ApplicationName = "TUM-Sovereign-Bank",
                    Environment = "Production",
                    EnableAutoPiiMasking = true,
                    EnableThreatDetection = true,
                    WormRetentionDays = 90
                };

                var storage = new TamperProofLogChain(options);
                var piiSanitizer = new TumPiiSanitizer();
                var threatDetector = new TumThreatDetector();
                var leakDetector = new OutboundLeakDetector(piiSanitizer, options);
                var endpointRegistry = new EndpointRegistry();
                var dispatcher = new LogSinkDispatcher(options, storage);
                var engine = new TumLogEngine(piiSanitizer, threatDetector, leakDetector, storage, dispatcher, endpointRegistry, options);

                var sigmaEngine = new SigmaRuleEngine();
                var riskEngine = new DynamicRiskEngine();
                var queryEngine = new EventQueryEngine();
                var analytics = new ThreatAnalyticsEngine(storage, sigmaEngine, null, options);

                var dispatchedAlerts = new List<AlertNotification>();
                var alertDispatcher = new AlertDispatcher(new[]
                {
                    new AlertChannelConfig
                    {
                        ChannelType = AlertChannelType.Discord,
                        WebhookUrl = "https://discord.mock/webhook",
                        MinimumRiskScore = 70.0
                    }
                });

                // 2. Register Community Sigma Rules
                var sqliRule = new SigmaRule
                {
                    Id = "rule-sqli-001",
                    Title = "Web SQL Injection UNION Attack",
                    Level = SigmaRuleLevel.Critical,
                    Tags = new List<string> { "attack.initial_access", "attack.t1190" },
                    Selections = new Dictionary<string, Dictionary<string, List<string>>>
                    {
                        ["selection"] = new Dictionary<string, List<string>>
                        {
                            ["PayloadSanitized|contains"] = new List<string> { "UNION SELECT", "OR 1=1" }
                        }
                    },
                    Condition = "selection"
                };
                sigmaEngine.RegisterRule(sqliRule);

                var mimikatzRule = new SigmaRule
                {
                    Id = "rule-mimi-002",
                    Title = "LSASS Memory Dump Mimikatz",
                    Level = SigmaRuleLevel.Critical,
                    Tags = new List<string> { "attack.credential_access", "attack.t1003.001" },
                    Selections = new Dictionary<string, Dictionary<string, List<string>>>
                    {
                        ["selection"] = new Dictionary<string, List<string>>
                        {
                            ["PayloadSanitized|contains"] = new List<string> { "sekurlsa::logonpasswords", "lsass.dmp" }
                        }
                    },
                    Condition = "selection"
                };
                sigmaEngine.RegisterRule(mimikatzRule);

                Assert.Equal(2, sigmaEngine.ActiveRuleCount);

                // 3. Ingest Events
                // Event A: Normal User Login
                var normalLog = await engine.LogAsync(new TumLogEntry
                {
                    LogId = "normal-1",
                    EventName = "AUTH.LOGIN",
                    Category = LogCategory.AuditTrail,
                    ClientIp = "192.168.1.100",
                    UserId = "somchai",
                    PayloadSanitized = "Somchai logged into banking portal"
                });
                var normalSigma = sigmaEngine.Evaluate(normalLog);
                var normalRisk = riskEngine.EvaluateRisk(normalLog, normalSigma);
                analytics.RecordEvent(normalLog, normalSigma);

                Assert.Empty(normalSigma);
                Assert.Equal(0.0, normalRisk.Score);
                Assert.False(normalRisk.ShouldAlert(70.0));

                // Event B: SQL Injection Exploit with Citizen ID PII Leak
                var sqliLog = await engine.LogAsync(new TumLogEntry
                {
                    LogId = "sqli-2",
                    EventName = "HTTP.REQUEST",
                    Category = LogCategory.SecurityThreat,
                    Severity = "Critical",
                    ClientIp = "185.220.101.5",
                    RequestPath = "/api/v1/auth/login",
                    PayloadSanitized = "POST /api/v1/auth/login id=1 UNION SELECT password FROM users-- 1100701234561"
                });
                var sqliSigma = sigmaEngine.Evaluate(sqliLog);
                var sqliRisk = riskEngine.EvaluateRisk(sqliLog, sqliSigma);
                analytics.RecordEvent(sqliLog, sqliSigma);

                // Verify PII Sanitization
                Assert.DoesNotContain("1100701234561", sqliLog.PayloadSanitized);
                Assert.Contains("1-XXXX-XXXXX-XX-1", sqliLog.PayloadSanitized);
                Assert.True(sqliLog.PiiRedactedCount >= 1);

                // Verify Sigma match & Risk
                Assert.Single(sqliSigma);
                Assert.Equal("rule-sqli-001", sqliSigma[0].RuleId);
                Assert.True(sqliRisk.Score >= 70.0);
                Assert.Equal(RiskSeverityBand.Critical, sqliRisk.SeverityBand);
                Assert.True(sqliRisk.ShouldAlert(70.0));

                // 4. Query Explorer Execution
                var allLogs = await storage.GetRecentEntriesAsync(10);
                var queryResult = queryEngine.ExecuteQuery(allLogs, new EventQueryRequest
                {
                    Query = "category:SecurityThreat AND severity:Critical"
                });

                Assert.Single(queryResult.Items);
                Assert.Equal("sqli-2", queryResult.Items[0].LogId);

                // 5. Threat Analytics & Live Attack Graph
                var dashboardSummary = analytics.GetDashboardSummary();
                Assert.Equal(2, dashboardSummary.TotalEventsIngested);
                Assert.Equal(1, dashboardSummary.CriticalAlertsCount);
                Assert.True(dashboardSummary.TopAttackerIps.ContainsKey("185.220.101.5"));
                Assert.True(dashboardSummary.MitreTechniquesSummary.ContainsKey("T1190"));

                var attackGraph = analytics.GetAttackGraph(50);
                Assert.Contains(attackGraph.Nodes, n => n.Label == "185.220.101.5" && n.Type == "AttackerIp");
                Assert.Contains(attackGraph.Nodes, n => n.Label == "/api/v1/auth/login" && n.Type == "TargetAsset");
                Assert.Contains(attackGraph.Nodes, n => n.Label == "T1190" && n.Type == "MitreTechnique");

                // 6. Cryptographic Chain & Compliance Audit Verification
                bool chainIntact = await storage.VerifyChainIntegrityAsync();
                Assert.True(chainIntact);

                var complianceAudit = await analytics.GenerateComplianceAuditAsync();
                Assert.True(complianceAudit.ComputerCrimeActSec26Compliant);
                Assert.True(complianceAudit.ThaiPdpaCompliant);
                Assert.True(complianceAudit.Iso27001Compliant);
                Assert.Equal("time.navy.mi.th", complianceAudit.NtpServerHost);
                Assert.NotEmpty(complianceAudit.ImmutableWormChainHead);
                Assert.NotEmpty(complianceAudit.GlobalMerkleRoot);
            }
            finally
            {
                if (Directory.Exists(testDir))
                {
                    try { Directory.Delete(testDir, true); } catch { }
                }
            }
        }
    }
}
