// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Tum.Trust.Security.Core.Models.Alerts;
using Tum.Trust.Security.Core.Models.Risk;
using Tum.Trust.Security.Infrastructure.Alerts;
using Xunit;

namespace Tum.Trust.Security.Tests
{
    public class AlertDispatcherTests
    {
        private class MockHttpMessageHandler : HttpMessageHandler
        {
            public List<HttpRequestMessage> Requests { get; } = new();
            public List<string> RequestBodies { get; } = new();

            protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            {
                Requests.Add(request);
                if (request.Content != null)
                {
                    string body = await request.Content.ReadAsStringAsync(cancellationToken);
                    RequestBodies.Add(body);
                }

                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent("{\"ok\":true}")
                };
            }
        }

        [Fact]
        public void FormatPayloadForChannel_FormatsDiscordEmbedCorrectly()
        {
            var alert = new AlertNotification
            {
                AlertId = "alert-001",
                Title = "Active Ransomware Canary Access",
                Description = "Canary file touched in sensitive volume",
                RiskScore = 95.0,
                SeverityBand = RiskSeverityBand.Critical,
                ClientIp = "10.10.10.25",
                Environment = "Production",
                StandardAction = "FILE.TOUCH",
                MitreTechniques = new List<string> { "T1486" }
            };

            string json = AlertDispatcher.FormatPayloadForChannel(alert, AlertChannelType.Discord);

            Assert.Contains("TUM-OpenSIEM Sentinel", json);
            Assert.Contains("Active Ransomware Canary Access", json);
            Assert.Contains("95.0 / 100", json);
            Assert.Contains("10.10.10.25", json);
            Assert.Contains("T1486", json);
            Assert.Contains("15158332", json); // 0xE74C3C in decimal
        }

        [Fact]
        public void FormatPayloadForChannel_FormatsSlackBlockKitCorrectly()
        {
            var alert = new AlertNotification
            {
                AlertId = "alert-002",
                Title = "Credential Dumping via Mimikatz",
                Description = "LSASS process memory read access",
                RiskScore = 88.0,
                SeverityBand = RiskSeverityBand.High,
                ClientIp = "192.168.1.10",
                Environment = "Production"
            };

            string json = AlertDispatcher.FormatPayloadForChannel(alert, AlertChannelType.Slack);

            Assert.Contains("Credential Dumping via Mimikatz", json);
            Assert.Contains("header", json);
            Assert.Contains("mrkdwn", json);
            Assert.Contains("88.0 / 100", json);
            Assert.Contains("192.168.1.10", json);
        }

        [Fact]
        public async Task DispatchAlertAsync_FiltersByMinimumRiskScore_AndSendsSuccessfully()
        {
            var handler = new MockHttpMessageHandler();
            var httpClient = new HttpClient(handler);

            var dispatcher = new AlertDispatcher(
                new[]
                {
                    new AlertChannelConfig
                    {
                        ChannelType = AlertChannelType.Discord,
                        WebhookUrl = "https://discord.com/api/webhooks/mock1",
                        MinimumRiskScore = 70.0 // Requires High/Critical
                    },
                    new AlertChannelConfig
                    {
                        ChannelType = AlertChannelType.Slack,
                        WebhookUrl = "https://hooks.slack.com/services/mock2",
                        MinimumRiskScore = 90.0 // Requires Critical only
                    }
                },
                httpClient);

            // High risk alert (80.0): Discord should receive it, Slack should NOT
            var highAlert = new AlertNotification
            {
                AlertId = "high-01",
                Title = "Suspicious Reconnaissance Scan",
                RiskScore = 80.0,
                SeverityBand = RiskSeverityBand.High
            };

            int count = await dispatcher.DispatchAlertAsync(highAlert);

            Assert.Equal(1, count);
            Assert.Single(handler.Requests);
            Assert.Equal("https://discord.com/api/webhooks/mock1", handler.Requests[0].RequestUri!.ToString());

            // Critical risk alert (95.0): BOTH Discord and Slack should receive it
            handler.Requests.Clear();
            var critAlert = new AlertNotification
            {
                AlertId = "crit-01",
                Title = "Critical Data Breach",
                RiskScore = 95.0,
                SeverityBand = RiskSeverityBand.Critical
            };

            int critCount = await dispatcher.DispatchAlertAsync(critAlert);

            Assert.Equal(2, critCount);
            Assert.Equal(2, handler.Requests.Count);
        }
    }
}
