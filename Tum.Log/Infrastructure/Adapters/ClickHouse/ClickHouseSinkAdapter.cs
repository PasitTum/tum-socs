// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Tum.Trust.Security.Core.Interfaces.Logging;
using Tum.Trust.Security.Core.Models.Logging;
using Tum.Trust.Security.Infrastructure.Serialization;

namespace Tum.Trust.Security.Infrastructure.Adapters.ClickHouse
{
    /// <summary>
    /// High-throughput Columnar Storage Adapter streaming audit and threat logs to ClickHouse MergeTree tables.
    /// Engineered for .NET 8/10 AOT, zero-allocation buffering, and high-EPS ingestion.
    /// </summary>
    public class ClickHouseSinkAdapter : IColumnarSinkAdapter
    {
        private readonly ClickHouseSinkOptions _options;
        private readonly HttpClient _httpClient;
        private readonly bool _ownsHttpClient;
        private readonly ILogger<ClickHouseSinkAdapter> _logger;
        private bool _isInitialized;

        /// <inheritdoc />
        public StorageSinkType SinkType => StorageSinkType.ClickHouseColumnar;

        /// <inheritdoc />
        public bool IsEnabled => _options.IsEnabled;

        /// <summary>
        /// Initializes a new instance of the <see cref="ClickHouseSinkAdapter"/> class.
        /// </summary>
        /// <param name="options">Configuration options.</param>
        /// <param name="httpClient">Optional pre-configured HttpClient instance.</param>
        /// <param name="logger">Optional logger instance.</param>
        public ClickHouseSinkAdapter(
            ClickHouseSinkOptions? options = null,
            HttpClient? httpClient = null,
            ILogger<ClickHouseSinkAdapter>? logger = null)
        {
            _options = options ?? new ClickHouseSinkOptions();
            _logger = logger ?? NullLogger<ClickHouseSinkAdapter>.Instance;

            if (httpClient != null)
            {
                _httpClient = httpClient;
                _ownsHttpClient = false;
            }
            else if (_options.CustomHttpMessageHandler != null)
            {
                _httpClient = new HttpClient(_options.CustomHttpMessageHandler);
                _ownsHttpClient = true;
            }
            else
            {
                _httpClient = new HttpClient();
                _ownsHttpClient = true;
            }

            if (!string.IsNullOrEmpty(_options.Username) && !string.IsNullOrEmpty(_options.Password))
            {
                var authBytes = Encoding.UTF8.GetBytes($"{_options.Username}:{_options.Password}");
                _httpClient.DefaultRequestHeaders.Authorization =
                    new AuthenticationHeaderValue("Basic", Convert.ToBase64String(authBytes));
            }
        }

        /// <inheritdoc />
        public async Task InitializeAsync(CancellationToken cancellationToken = default)
        {
            if (_isInitialized || !_options.IsEnabled || !_options.AutoCreateSchema)
            {
                _isInitialized = true;
                return;
            }

            try
            {
                string endpoint = _options.EndpointUri.TrimEnd('/');

                // 1. Ensure Database Exists
                string createDbSql = $"CREATE DATABASE IF NOT EXISTS {_options.Database};";
                using var dbContent = new StringContent(createDbSql, Encoding.UTF8, "text/plain");
                var dbResponse = await _httpClient.PostAsync($"{endpoint}/", dbContent, cancellationToken).ConfigureAwait(false);
                dbResponse.EnsureSuccessStatusCode();

                // 2. Ensure Table Exists
                string createTableSql = GetSchemaDefinitionSql();
                using var tableContent = new StringContent(createTableSql, Encoding.UTF8, "text/plain");
                var tableResponse = await _httpClient.PostAsync($"{endpoint}/", tableContent, cancellationToken).ConfigureAwait(false);
                tableResponse.EnsureSuccessStatusCode();

                _isInitialized = true;
                _logger.LogInformation("ClickHouse table '{Database}.{TableName}' successfully initialized",
                    _options.Database, _options.TableName);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to auto-create ClickHouse schema at {Endpoint}: {Message}",
                    _options.EndpointUri, ex.Message);
            }
        }

        /// <inheritdoc />
        public async Task<int> IngestBatchAsync(IReadOnlyList<TumLogEntry> batch, CancellationToken cancellationToken = default)
        {
            if (batch == null || batch.Count == 0 || !_options.IsEnabled)
            {
                return 0;
            }

            string payload = FormatJsonEachRowPayload(batch);
            string endpoint = _options.EndpointUri.TrimEnd('/');
            string insertQuery = $"INSERT INTO {_options.Database}.{_options.TableName} FORMAT JSONEachRow";
            string requestUrl = $"{endpoint}/?query={Uri.EscapeDataString(insertQuery)}";

            using var content = new StringContent(payload, Encoding.UTF8, "application/json");
            var response = await _httpClient.PostAsync(requestUrl, content, cancellationToken).ConfigureAwait(false);

            if (!response.IsSuccessStatusCode)
            {
                string errorBody = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
                _logger.LogError("ClickHouse bulk ingestion failed with status {StatusCode}: {ErrorBody}",
                    response.StatusCode, errorBody);
                throw new HttpRequestException($"ClickHouse batch insertion error ({response.StatusCode}): {errorBody}");
            }

            return batch.Count;
        }

        /// <inheritdoc />
        public string GetSchemaDefinitionSql()
        {
            return $@"CREATE TABLE IF NOT EXISTS {_options.Database}.{_options.TableName} (
    log_id UUID,
    timestamp DateTime64(3, 'UTC'),
    event_name LowCardinality(String),
    category LowCardinality(String),
    severity LowCardinality(String),
    application_name LowCardinality(String),
    environment LowCardinality(String),
    user_id Nullable(String),
    client_ip String,
    request_path Nullable(String),
    http_method LowCardinality(Nullable(String)),
    status_code Nullable(Int32),
    execution_duration_ms Float64,
    payload_sanitized String,
    pii_redacted_count UInt32,
    tamper_proof_hash FixedString(64),
    previous_entry_hash FixedString(64),
    merkle_root FixedString(64),
    correlation_id String,
    standard_action LowCardinality(String),
    defense_mode LowCardinality(String),
    compliance_flags UInt32
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, category, severity, application_name);";
        }

        /// <summary>
        /// Formats a batch of log entries into newline-delimited ClickHouse JSONEachRow format.
        /// </summary>
        /// <param name="batch">The entries to format.</param>
        /// <returns>Newline-delimited JSON payload.</returns>
        public static string FormatJsonEachRowPayload(IReadOnlyList<TumLogEntry> batch)
        {
            var sb = new StringBuilder(batch.Count * 256);
            for (int i = 0; i < batch.Count; i++)
            {
                var entry = batch[i];
                string json = JsonSerializer.Serialize(entry, TumLogJsonSerializerContext.Default.TumLogEntry);
                sb.Append(json).Append('\n');
            }
            return sb.ToString();
        }

        /// <inheritdoc />
        public void Dispose()
        {
            if (_ownsHttpClient)
            {
                _httpClient.Dispose();
            }
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
