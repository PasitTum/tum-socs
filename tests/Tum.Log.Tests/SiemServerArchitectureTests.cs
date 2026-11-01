// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Tum.Siem.Server.Configuration;
using Tum.Siem.Server.Controllers;
using Tum.Siem.Server.DTOs.Requests;
using Tum.Siem.Server.DTOs.Responses;
using Tum.Siem.Server.Services;
using Tum.Trust.Security.Core.Models.Alerts;
using Tum.Trust.Security.Core.Models.Logging;
using Tum.Trust.Security.Infrastructure.Alerts;
using Tum.Trust.Security.Infrastructure.Analytics;
using Tum.Trust.Security.Infrastructure.Logging;
using Tum.Trust.Security.Infrastructure.Query;
using Tum.Trust.Security.Infrastructure.Risk;
using Tum.Trust.Security.Infrastructure.Sigma;
using Xunit;

namespace Tum.Trust.Security.Tests
{
    public class SiemServerArchitectureTests
    {
        [Fact]
        public void SigmaRuleLoaderService_Should_Load_And_Register_Rules()
        {
            var sigmaEngine = new SigmaRuleEngine();
            var options = Options.Create(new SiemServerOptions { RulesDirectory = "rules" });
            var loader = new SigmaRuleLoaderService(sigmaEngine, options, NullLogger<SigmaRuleLoaderService>.Instance);

            int loaded = loader.LoadAllRules();
            Assert.True(loaded >= 0);

            // Test dynamic yaml registration
            string customRuleYaml = @"
title: Dynamic Detection Test
id: 11112222-3333-4444-5555-666677778888
status: stable
level: critical
tags:
    - attack.execution
detection:
    selection:
        payloadSanitized|contains: 'DUMP_MEMORY'
    condition: selection
";
            var rule = loader.RegisterFromYaml(customRuleYaml);
            Assert.NotNull(rule);
            Assert.Equal("Dynamic Detection Test", rule.Title);
            Assert.Equal("11112222-3333-4444-5555-666677778888", rule.Id);
        }

        [Fact]
        public async Task EventIngestionPipeline_Should_Process_Log_And_Return_Response()
        {
            string testDir = Path.Combine(Path.GetTempPath(), "pipeline_test_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(testDir);

            try
            {
                var tumOptions = new TumLogOptions { StorageDirectory = testDir };
                var storage = new TamperProofLogChain(tumOptions);
                var piiSanitizer = new TumPiiSanitizer();
                var threatDetector = new TumThreatDetector();
                var leakDetector = new OutboundLeakDetector(piiSanitizer, tumOptions);
                var endpointRegistry = new EndpointRegistry();
                var dispatcher = new LogSinkDispatcher(tumOptions, storage);
                var engine = new TumLogEngine(piiSanitizer, threatDetector, leakDetector, storage, dispatcher, endpointRegistry, tumOptions);

                var sigmaEngine = new SigmaRuleEngine();
                var riskEngine = new DynamicRiskEngine();
                var analytics = new ThreatAnalyticsEngine(storage, sigmaEngine, null, tumOptions);
                var alertDispatcher = new AlertDispatcher(Array.Empty<AlertChannelConfig>());
                var siemOptions = Options.Create(new SiemServerOptions { AlertRiskThreshold = 70.0 });

                var pipeline = new EventIngestionPipeline(
                    engine,
                    sigmaEngine,
                    riskEngine,
                    analytics,
                    alertDispatcher,
                    siemOptions,
                    NullLogger<EventIngestionPipeline>.Instance);

                var entry = new TumLogEntry
                {
                    EventName = "HTTP.REQUEST",
                    Category = LogCategory.SecurityThreat,
                    Severity = "Critical",
                    ClientIp = "185.220.101.5",
                    RequestPath = "/login",
                    PayloadSanitized = "user=admin' UNION SELECT password FROM users--"
                };

                var response = await pipeline.IngestAsync(entry);

                Assert.NotNull(response);
                Assert.False(string.IsNullOrEmpty(response.LogId));
                Assert.False(string.IsNullOrEmpty(response.TamperProofHash));
                Assert.True(response.RiskScore >= 0);
            }
            finally
            {
                if (Directory.Exists(testDir))
                {
                    try { Directory.Delete(testDir, true); } catch { }
                }
            }
        }

        [Fact]
        public async Task StatusController_Should_Return_Operational_Status()
        {
            string testDir = Path.Combine(Path.GetTempPath(), "status_test_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(testDir);

            try
            {
                var tumOptions = new TumLogOptions { StorageDirectory = testDir };
                var storage = new TamperProofLogChain(tumOptions);
                var sigmaEngine = new SigmaRuleEngine();
                var siemOptions = Options.Create(new SiemServerOptions());

                var controller = new StatusController(storage, sigmaEngine, tumOptions, siemOptions);
                var actionResult = await controller.GetStatus(CancellationToken.None);

                var okResult = Assert.IsType<OkObjectResult>(actionResult);
                var status = Assert.IsType<SystemStatusResponse>(okResult.Value);

                Assert.Equal("Operational", status.Status);
                Assert.Equal("TUM-OpenSIEM Sovereign Edition", status.Engine);
                Assert.True(status.ChainIntact);
            }
            finally
            {
                if (Directory.Exists(testDir))
                {
                    try { Directory.Delete(testDir, true); } catch { }
                }
            }
        }

        [Fact]
        public async Task DashboardController_Should_Return_Summary_Graph_And_Compliance()
        {
            string testDir = Path.Combine(Path.GetTempPath(), "dash_test_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(testDir);

            try
            {
                var tumOptions = new TumLogOptions { StorageDirectory = testDir };
                var storage = new TamperProofLogChain(tumOptions);
                var sigmaEngine = new SigmaRuleEngine();
                var analytics = new ThreatAnalyticsEngine(storage, sigmaEngine, null, tumOptions);

                var controller = new DashboardController(analytics);

                var summaryResult = Assert.IsType<OkObjectResult>(controller.GetSummary());
                Assert.NotNull(summaryResult.Value);

                var graphResult = Assert.IsType<OkObjectResult>(controller.GetAttackGraph(25));
                Assert.NotNull(graphResult.Value);

                var complianceResult = Assert.IsType<OkObjectResult>(await controller.GetComplianceReport());
                Assert.NotNull(complianceResult.Value);
            }
            finally
            {
                if (Directory.Exists(testDir))
                {
                    try { Directory.Delete(testDir, true); } catch { }
                }
            }
        }

        [Fact]
        public async Task LogsController_Should_Ingest_And_Query_Logs()
        {
            string testDir = Path.Combine(Path.GetTempPath(), "logs_ctrl_test_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(testDir);

            try
            {
                var tumOptions = new TumLogOptions { StorageDirectory = testDir };
                var storage = new TamperProofLogChain(tumOptions);
                var piiSanitizer = new TumPiiSanitizer();
                var threatDetector = new TumThreatDetector();
                var leakDetector = new OutboundLeakDetector(piiSanitizer, tumOptions);
                var endpointRegistry = new EndpointRegistry();
                var dispatcher = new LogSinkDispatcher(tumOptions, storage);
                var engine = new TumLogEngine(piiSanitizer, threatDetector, leakDetector, storage, dispatcher, endpointRegistry, tumOptions);

                var sigmaEngine = new SigmaRuleEngine();
                var riskEngine = new DynamicRiskEngine();
                var analytics = new ThreatAnalyticsEngine(storage, sigmaEngine, null, tumOptions);
                var queryEngine = new EventQueryEngine();
                var alertDispatcher = new AlertDispatcher(Array.Empty<AlertChannelConfig>());
                var siemOptions = Options.Create(new SiemServerOptions());

                var pipeline = new EventIngestionPipeline(engine, sigmaEngine, riskEngine, analytics, alertDispatcher, siemOptions, NullLogger<EventIngestionPipeline>.Instance);
                var controller = new LogsController(pipeline, storage, queryEngine);

                var entry = new TumLogEntry
                {
                    EventName = "TEST.EVENT",
                    Category = LogCategory.AuditTrail,
                    ClientIp = "10.0.0.99",
                    PayloadSanitized = "Test Payload"
                };

                var ingestResult = Assert.IsType<OkObjectResult>(await controller.Ingest(entry, CancellationToken.None));
                Assert.NotNull(ingestResult.Value);

                var queryResult = Assert.IsType<OkObjectResult>(await controller.Query(new QueryLogsRequest { Query = "*" }));
                Assert.NotNull(queryResult.Value);

                var liveResult = Assert.IsType<OkObjectResult>(await controller.GetLiveFeed(10));
                Assert.NotNull(liveResult.Value);
            }
            finally
            {
                if (Directory.Exists(testDir))
                {
                    try { Directory.Delete(testDir, true); } catch { }
                }
            }
        }

        [Fact]
        public void AuthService_Should_Authenticate_And_Validate_Tokens()
        {
            var auth = new AuthService(NullLogger<AuthService>.Instance);

            // Valid login
            var res = auth.Authenticate(new LoginRequest { Username = "admin", Password = "TumAdmin2026!#" });
            Assert.NotNull(res);
            Assert.False(string.IsNullOrEmpty(res.Token));
            Assert.Equal("Administrator", res.User.Role);

            // Validate token
            var profile = auth.ValidateToken(res.Token);
            Assert.NotNull(profile);
            Assert.Equal("admin", profile.Username);

            // Invalid login
            var invalid = auth.Authenticate(new LoginRequest { Username = "admin", Password = "WrongPassword" });
            Assert.Null(invalid);
        }

        [Fact]
        public async Task DatasetIngestionService_Should_Load_And_Purge_Data()
        {
            string testDir = Path.Combine(Path.GetTempPath(), "dataset_test_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(testDir);

            try
            {
                var tumOptions = new TumLogOptions { StorageDirectory = testDir };
                var storage = new TamperProofLogChain(tumOptions);
                var piiSanitizer = new TumPiiSanitizer();
                var threatDetector = new TumThreatDetector();
                var leakDetector = new OutboundLeakDetector(piiSanitizer, tumOptions);
                var endpointRegistry = new EndpointRegistry();
                var dispatcher = new LogSinkDispatcher(tumOptions, storage);
                var engine = new TumLogEngine(piiSanitizer, threatDetector, leakDetector, storage, dispatcher, endpointRegistry, tumOptions);

                var sigmaEngine = new SigmaRuleEngine();
                var riskEngine = new DynamicRiskEngine();
                var analytics = new ThreatAnalyticsEngine(storage, sigmaEngine, null, tumOptions);
                var alertDispatcher = new AlertDispatcher(Array.Empty<AlertChannelConfig>());
                var siemOptions = Options.Create(new SiemServerOptions { StorageDirectory = testDir });

                var pipeline = new EventIngestionPipeline(engine, sigmaEngine, riskEngine, analytics, alertDispatcher, siemOptions, NullLogger<EventIngestionPipeline>.Instance);
                var datasetService = new DatasetIngestionService(pipeline, storage, siemOptions, NullLogger<DatasetIngestionService>.Instance);

                // Catalog check
                var catalog = datasetService.GetCatalog();
                Assert.NotEmpty(catalog.Datasets);

                // Ingest sample attack dataset
                var loadResult = await datasetService.LoadDatasetAsync(new LoadDatasetRequest { DatasetId = "web_cve_exploits", Limit = 5 });
                Assert.True(loadResult.Success);
                Assert.True(loadResult.IngestedCount > 0);

                // Purge check (production reset)
                var purgeResult = await datasetService.PurgeAllDataAsync();
                Assert.True(purgeResult.Success);
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
