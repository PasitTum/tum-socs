// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Tum.Trust.Security.Core.Models.Logging;
using Tum.Trust.Security.Infrastructure.Adapters.DuckDB;
using Xunit;

namespace Tum.Trust.Security.Tests
{
    public class DuckDbSinkAdapterTests
    {
        [Fact]
        public void GetSchemaDefinitionSql_ReturnsValidDuckDbDDL()
        {
            var options = new DuckDbSinkOptions
            {
                TableName = "edge_security_logs"
            };

            var adapter = new DuckDbSinkAdapter(options);
            string ddl = adapter.GetSchemaDefinitionSql();

            Assert.Contains("CREATE TABLE IF NOT EXISTS edge_security_logs", ddl);
            Assert.Contains("log_id VARCHAR PRIMARY KEY", ddl);
            Assert.Contains("timestamp TIMESTAMP WITH TIME ZONE", ddl);
            Assert.Contains("tamper_proof_hash VARCHAR(64)", ddl);
        }

        [Fact]
        public void FormatBatchInsertSql_EscapesQuotesAndGeneratesValidSyntax()
        {
            var options = new DuckDbSinkOptions { TableName = "audit_events" };
            var adapter = new DuckDbSinkAdapter(options);

            var batch = new List<TumLogEntry>
            {
                new TumLogEntry
                {
                    LogId = "log-001",
                    EventName = "QUERY.SQL",
                    Category = LogCategory.AuditTrail,
                    ClientIp = "127.0.0.1",
                    PayloadSanitized = "SELECT * FROM users WHERE name = 'O''Reilly';"
                }
            };

            string sql = adapter.FormatBatchInsertSql(batch);

            Assert.StartsWith("INSERT INTO audit_events VALUES (", sql);
            Assert.EndsWith(");", sql);
            Assert.Contains("'log-001'", sql);
            Assert.Contains("O''''Reilly", sql);
        }

        [Fact]
        public async Task IngestBatchAsync_ExecutesViaCustomCommandExecutor()
        {
            string? capturedSql = null;
            var options = new DuckDbSinkOptions
            {
                TableName = "telemetry_logs",
                CustomCommandExecutor = (sql, ct) =>
                {
                    capturedSql = sql;
                    return Task.FromResult(1);
                }
            };

            var adapter = new DuckDbSinkAdapter(options);
            var batch = new List<TumLogEntry>
            {
                new TumLogEntry
                {
                    LogId = "exec-test-1",
                    EventName = "SYSTEM.BOOT",
                    Category = LogCategory.SystemDiagnostic
                }
            };

            int count = await adapter.IngestBatchAsync(batch);

            Assert.Equal(1, count);
            Assert.NotNull(capturedSql);
            Assert.Contains("INSERT INTO telemetry_logs VALUES", capturedSql);
            Assert.Contains("exec-test-1", capturedSql);
        }

        [Fact]
        public async Task IngestBatchAsync_WritesStagingJournalFileWhenNoExecutor()
        {
            string testDir = Path.Combine(Path.GetTempPath(), "tum_duckdb_test_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(testDir);

            try
            {
                var options = new DuckDbSinkOptions
                {
                    DatabasePath = Path.Combine(testDir, "test.duckdb"),
                    TableName = "journal_logs"
                };

                var adapter = new DuckDbSinkAdapter(options);
                var batch = new List<TumLogEntry>
                {
                    new TumLogEntry
                    {
                        LogId = "journal-01",
                        EventName = "KERNEL.PROBE",
                        Category = LogCategory.SystemDiagnostic
                    }
                };

                int count = await adapter.IngestBatchAsync(batch);

                Assert.Equal(1, count);
                var sqlFiles = Directory.GetFiles(testDir, "*.sql");
                Assert.NotEmpty(sqlFiles);

                string content = await File.ReadAllTextAsync(sqlFiles[0]);
                Assert.Contains("INSERT INTO journal_logs VALUES", content);
                Assert.Contains("journal-01", content);
            }
            finally
            {
                if (Directory.Exists(testDir))
                {
                    Directory.Delete(testDir, true);
                }
            }
        }
    }
}
