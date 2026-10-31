// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Tum.Trust.Security.Core.Interfaces.Logging;
using Tum.Trust.Security.Core.Models.Logging;

namespace Tum.Trust.Security.Infrastructure.Adapters.DuckDB
{
    /// <summary>
    /// Embedded Columnar Storage Adapter streaming audit and threat telemetry to DuckDB.
    /// Optimized for edge deployments, offline nodes, and ultra-fast vectorized OLAP queries.
    /// </summary>
    public class DuckDbSinkAdapter : IColumnarSinkAdapter
    {
        private readonly DuckDbSinkOptions _options;
        private readonly ILogger<DuckDbSinkAdapter> _logger;
        private bool _isInitialized;
        private readonly SemaphoreSlim _lock = new(1, 1);

        /// <inheritdoc />
        public StorageSinkType SinkType => StorageSinkType.DuckDbEmbedded;

        /// <inheritdoc />
        public bool IsEnabled => _options.IsEnabled;

        /// <summary>
        /// Initializes a new instance of the <see cref="DuckDbSinkAdapter"/> class.
        /// </summary>
        /// <param name="options">Configuration options.</param>
        /// <param name="logger">Optional logger instance.</param>
        public DuckDbSinkAdapter(
            DuckDbSinkOptions? options = null,
            ILogger<DuckDbSinkAdapter>? logger = null)
        {
            _options = options ?? new DuckDbSinkOptions();
            _logger = logger ?? NullLogger<DuckDbSinkAdapter>.Instance;
        }

        /// <inheritdoc />
        public async Task InitializeAsync(CancellationToken cancellationToken = default)
        {
            if (_isInitialized || !_options.IsEnabled)
            {
                _isInitialized = true;
                return;
            }

            await _lock.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                if (_options.AutoCreateSchema && _options.CustomCommandExecutor != null)
                {
                    string ddl = GetSchemaDefinitionSql();
                    await _options.CustomCommandExecutor(ddl, cancellationToken).ConfigureAwait(false);
                    _logger.LogInformation("DuckDB table '{TableName}' schema initialized successfully", _options.TableName);
                }

                _isInitialized = true;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to initialize DuckDB schema: {Message}", ex.Message);
            }
            finally
            {
                _lock.Release();
            }
        }

        /// <inheritdoc />
        public async Task<int> IngestBatchAsync(IReadOnlyList<TumLogEntry> batch, CancellationToken cancellationToken = default)
        {
            if (batch == null || batch.Count == 0 || !_options.IsEnabled)
            {
                return 0;
            }

            string insertSql = FormatBatchInsertSql(batch);

            if (_options.CustomCommandExecutor != null)
            {
                await _options.CustomCommandExecutor(insertSql, cancellationToken).ConfigureAwait(false);
                return batch.Count;
            }

            // Fallback: write to staging journal directory for DuckDB batch import
            string stagingDir = Path.GetDirectoryName(_options.DatabasePath) ?? ".";
            if (!string.IsNullOrEmpty(stagingDir) && !Directory.Exists(stagingDir))
            {
                Directory.CreateDirectory(stagingDir);
            }

            string journalFile = Path.Combine(stagingDir, $"{Path.GetFileNameWithoutExtension(_options.DatabasePath)}_batch_{DateTime.UtcNow:yyyyMMdd_HHmmss}.sql");
            await File.AppendAllTextAsync(journalFile, insertSql + Environment.NewLine, Encoding.UTF8, cancellationToken).ConfigureAwait(false);

            return batch.Count;
        }

        /// <inheritdoc />
        public string GetSchemaDefinitionSql()
        {
            return $@"CREATE TABLE IF NOT EXISTS {_options.TableName} (
    log_id VARCHAR PRIMARY KEY,
    timestamp TIMESTAMP WITH TIME ZONE,
    event_name VARCHAR,
    category VARCHAR,
    severity VARCHAR,
    application_name VARCHAR,
    environment VARCHAR,
    user_id VARCHAR,
    client_ip VARCHAR,
    request_path VARCHAR,
    http_method VARCHAR,
    status_code INTEGER,
    execution_duration_ms DOUBLE,
    payload_sanitized VARCHAR,
    pii_redacted_count INTEGER,
    tamper_proof_hash VARCHAR(64),
    previous_entry_hash VARCHAR(64),
    merkle_root VARCHAR(64),
    correlation_id VARCHAR,
    standard_action VARCHAR,
    defense_mode VARCHAR,
    compliance_flags BIGINT
);";
        }

        /// <summary>
        /// Formats a batch of log entries into a multi-row DuckDB SQL INSERT statement.
        /// </summary>
        /// <param name="batch">Entries to insert.</param>
        /// <returns>SQL INSERT statement.</returns>
        public string FormatBatchInsertSql(IReadOnlyList<TumLogEntry> batch)
        {
            var sb = new StringBuilder(batch.Count * 256);
            sb.Append($"INSERT INTO {_options.TableName} VALUES ");

            for (int i = 0; i < batch.Count; i++)
            {
                if (i > 0)
                {
                    sb.Append(", ");
                }

                var e = batch[i];
                sb.Append('(');
                sb.Append(SqlEscape(e.LogId)).Append(", ");
                sb.Append('\'').Append(e.TimestampUtc.ToString("yyyy-MM-dd HH:mm:ss.fffzzz")).Append("', ");
                sb.Append(SqlEscape(e.EventName)).Append(", ");
                sb.Append(SqlEscape(e.Category.ToString())).Append(", ");
                sb.Append(SqlEscape(e.Severity)).Append(", ");
                sb.Append(SqlEscape(e.ApplicationName)).Append(", ");
                sb.Append(SqlEscape(e.Environment)).Append(", ");
                sb.Append(SqlNullableEscape(e.UserId)).Append(", ");
                sb.Append(SqlEscape(e.ClientIp)).Append(", ");
                sb.Append(SqlNullableEscape(e.RequestPath)).Append(", ");
                sb.Append(SqlNullableEscape(e.HttpMethod)).Append(", ");
                sb.Append(e.StatusCode?.ToString() ?? "NULL").Append(", ");
                sb.Append(e.ExecutionDurationMs.ToString("F3", System.Globalization.CultureInfo.InvariantCulture)).Append(", ");
                sb.Append(SqlEscape(e.PayloadSanitized)).Append(", ");
                sb.Append(e.PiiRedactedCount).Append(", ");
                sb.Append(SqlEscape(e.TamperProofHash)).Append(", ");
                sb.Append(SqlEscape(e.PreviousEntryHash)).Append(", ");
                sb.Append(SqlEscape(e.MerkleRoot)).Append(", ");
                sb.Append(SqlEscape(e.CorrelationId)).Append(", ");
                sb.Append(SqlEscape(e.StandardAction)).Append(", ");
                sb.Append(SqlEscape(e.DefenseModeApplied.ToString())).Append(", ");
                sb.Append((long)e.ComplianceFlags);
                sb.Append(')');
            }

            sb.Append(';');
            return sb.ToString();
        }

        private static string SqlEscape(string? value)
        {
            if (value == null) return "''";
            return "'" + value.Replace("'", "''") + "'";
        }

        private static string SqlNullableEscape(string? value)
        {
            if (value == null) return "NULL";
            return "'" + value.Replace("'", "''") + "'";
        }

        /// <inheritdoc />
        public void Dispose()
        {
            _lock.Dispose();
            GC.SuppressFinalize(this);
        }

        /// <inheritdoc />
        public ValueTask DisposeAsync()
        {
            Dispose();
            return ValueTask.CompletedTask;
        }
    }
}
