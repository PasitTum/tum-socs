// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Tum.Trust.Security.Core.Models.Logging;

namespace Tum.Trust.Security.Core.Interfaces.Logging
{
    /// <summary>
    /// Contract for high-throughput columnar storage sinks (ClickHouse, DuckDB) used in TUM-OpenSIEM.
    /// </summary>
    public interface IColumnarSinkAdapter : IAsyncDisposable, IDisposable
    {
        /// <summary>
        /// Gets the sink type (ClickHouseColumnar or DuckDbEmbedded).
        /// </summary>
        StorageSinkType SinkType { get; }

        /// <summary>
        /// Gets a value indicating whether this columnar sink is actively enabled.
        /// </summary>
        bool IsEnabled { get; }

        /// <summary>
        /// Asynchronously initializes database schemas, connection pools, or target tables.
        /// </summary>
        /// <param name="cancellationToken">Cancellation token.</param>
        Task InitializeAsync(CancellationToken cancellationToken = default);

        /// <summary>
        /// Ingests a batch of log records into the columnar store in a single bulk operation.
        /// </summary>
        /// <param name="batch">Batch of log entries.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Count of successfully written records.</returns>
        Task<int> IngestBatchAsync(IReadOnlyList<TumLogEntry> batch, CancellationToken cancellationToken = default);

        /// <summary>
        /// Returns the standard DDL SQL statement used to create the log schema table.
        /// </summary>
        string GetSchemaDefinitionSql();
    }
}
