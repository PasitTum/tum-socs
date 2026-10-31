// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Tum.Trust.Security.Core.Models.Logging;
using Tum.Trust.Security.Infrastructure.Adapters.ClickHouse;
using Xunit;

namespace Tum.Trust.Security.Tests
{
    public class ClickHouseSinkAdapterTests
    {
        private class MockHttpMessageHandler : HttpMessageHandler
        {
            public HttpRequestMessage? LastRequest { get; private set; }
            public string? LastRequestBody { get; private set; }

            protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            {
                LastRequest = request;
                if (request.Content != null)
                {
                    LastRequestBody = await request.Content.ReadAsStringAsync(cancellationToken);
                }

                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent("OK")
                };
            }
        }

        [Fact]
        public void GetSchemaDefinitionSql_ReturnsValidMergeTreeDDL()
        {
            var options = new ClickHouseSinkOptions
            {
                Database = "siem_test_db",
                TableName = "siem_logs"
            };

            var adapter = new ClickHouseSinkAdapter(options);
            string ddl = adapter.GetSchemaDefinitionSql();

            Assert.Contains("CREATE TABLE IF NOT EXISTS siem_test_db.siem_logs", ddl);
            Assert.Contains("ENGINE = MergeTree()", ddl);
            Assert.Contains("PARTITION BY toYYYYMM(timestamp)", ddl);
            Assert.Contains("ORDER BY (timestamp, category, severity, application_name)", ddl);
            Assert.Contains("tamper_proof_hash FixedString(64)", ddl);
        }

        [Fact]
        public void FormatJsonEachRowPayload_GeneratesNewlineDelimitedJson()
        {
            var entries = new List<TumLogEntry>
            {
                new TumLogEntry
                {
                    LogId = "test-log-1",
                    EventName = "AUTH.LOGIN",
                    Category = LogCategory.AuditTrail,
                    ClientIp = "192.168.1.100",
                    PayloadSanitized = "User login successful"
                },
                new TumLogEntry
                {
                    LogId = "test-log-2",
                    EventName = "DATA.EXPORT",
                    Category = LogCategory.PiiAccess,
                    ClientIp = "10.0.0.5",
                    PayloadSanitized = "Report exported"
                }
            };

            string payload = ClickHouseSinkAdapter.FormatJsonEachRowPayload(entries);
            string[] lines = payload.Trim().Split('\n');

            Assert.Equal(2, lines.Length);
            Assert.Contains("\"LogId\":\"test-log-1\"", lines[0]);
            Assert.Contains("\"EventName\":\"AUTH.LOGIN\"", lines[0]);
            Assert.Contains("\"LogId\":\"test-log-2\"", lines[1]);
            Assert.Contains("\"EventName\":\"DATA.EXPORT\"", lines[1]);
        }

        [Fact]
        public async Task IngestBatchAsync_DispatchesJsonEachRowToClickHouseHttp()
        {
            var mockHandler = new MockHttpMessageHandler();
            var options = new ClickHouseSinkOptions
            {
                EndpointUri = "http://clickhouse.internal:8123",
                Database = "siem_vault",
                TableName = "security_events",
                Username = "siem_admin",
                Password = "SecretPassword123!",
                CustomHttpMessageHandler = mockHandler
            };

            var adapter = new ClickHouseSinkAdapter(options);

            var batch = new List<TumLogEntry>
            {
                new TumLogEntry
                {
                    LogId = "clickhouse-entry-1",
                    EventName = "FIREWALL.DROP",
                    Category = LogCategory.SecurityThreat,
                    ClientIp = "203.0.113.15"
                }
            };

            int written = await adapter.IngestBatchAsync(batch);

            Assert.Equal(1, written);
            Assert.NotNull(mockHandler.LastRequest);
            string unescapedQuery = Uri.UnescapeDataString(mockHandler.LastRequest!.RequestUri!.Query);
            Assert.Contains("INSERT INTO siem_vault.security_events FORMAT JSONEachRow", unescapedQuery);
            Assert.NotNull(mockHandler.LastRequestBody);
            Assert.Contains("clickhouse-entry-1", mockHandler.LastRequestBody);
            Assert.NotNull(mockHandler.LastRequest.Headers.Authorization);
            Assert.Equal("Basic", mockHandler.LastRequest.Headers.Authorization!.Scheme);
        }
    }
}
