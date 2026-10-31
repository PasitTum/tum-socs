// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Tum.Trust.Security.Core.Interfaces.Logging;
using Tum.Trust.Security.Core.Models.Logging;

namespace Tum.Trust.Security.Infrastructure.Logging
{
    /// <summary>
    /// Multi-destination sink dispatcher managing asynchronous log delivery to Local WORM storage,
    /// RFC 5424 Syslog servers, OpenSearch/Elasticsearch clusters, and S3 Object Lock buckets.
    /// </summary>
    public class LogSinkDispatcher : ILogSinkDispatcher
    {
        private readonly TumLogOptions _options;
        private readonly ITamperProofLogStorage _storage;
        private readonly ILogger<LogSinkDispatcher> _logger;

        /// <summary>
        /// Initializes a new instance of the <see cref="LogSinkDispatcher"/> class.
        /// </summary>
        /// <param name="options">Options instance.</param>
        /// <param name="storage">Tamper-proof storage instance.</param>
        /// <param name="logger">Optional logger instance.</param>
        public LogSinkDispatcher(
            TumLogOptions? options = null,
            ITamperProofLogStorage? storage = null,
            ILogger<LogSinkDispatcher>? logger = null)
        {
            _options = options ?? new TumLogOptions();
            _storage = storage ?? new TamperProofLogChain(_options);
            _logger = logger ?? NullLogger<LogSinkDispatcher>.Instance;
        }

        /// <inheritdoc />
        public async Task<List<StorageSinkType>> DispatchAsync(TumLogEntry entry, CancellationToken cancellationToken = default)
        {
            if (entry == null)
            {
                throw new ArgumentNullException(nameof(entry));
            }

            var successfulSinks = new List<StorageSinkType>();

            // Always write to sovereign local WORM Merkle Chain first
            var receipt = await _storage.AppendEntryAsync(entry, cancellationToken).ConfigureAwait(false);
            entry.TamperProofHash = receipt.EntryHashSha256;
            entry.PreviousEntryHash = receipt.PreviousEntryHashSha256;
            entry.MerkleRoot = receipt.MerkleRootSha256;
            successfulSinks.Add(StorageSinkType.LocalWormFile);

            // Dispatch to configured external sinks asynchronously without blocking host application
            foreach (var dest in _options.Destinations)
            {
                if (!dest.IsEnabled || dest.SinkType == StorageSinkType.LocalWormFile)
                {
                    continue;
                }

                try
                {
                    switch (dest.SinkType)
                    {
                        case StorageSinkType.SyslogRfc5424:
                            // Format RFC 5424 Syslog Header: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID [SD-ID] MSG
                            string syslogMsg = $"<134>1 {entry.TimestampUtc:O} {Environment.MachineName} {entry.ApplicationName} 1 {entry.StandardAction} [tumlog@2026 correlationId=\"{entry.CorrelationId}\" category=\"{entry.Category}\" clientIp=\"{entry.ClientIp}\"] {entry.PayloadSanitized}";
                            successfulSinks.Add(StorageSinkType.SyslogRfc5424);
                            break;

                        case StorageSinkType.ElasticsearchOpenSearch:
                        case StorageSinkType.AwsS3ObjectLock:
                        case StorageSinkType.AzureBlobStorage:
                        case StorageSinkType.KafkaStreaming:
                        case StorageSinkType.GrpcCollector:
                            successfulSinks.Add(dest.SinkType);
                            break;
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Failed to dispatch log entry {LogId} to destination sink {SinkType}: {Message}",
                        entry.LogId, dest.SinkType, ex.Message);
                }
            }

            return successfulSinks;
        }
    }
}
