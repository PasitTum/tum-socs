// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using System.Threading;
using System.Threading.Tasks;

namespace Tum.Trust.Security.Infrastructure.Adapters.DuckDB
{
    /// <summary>
    /// Configuration options for the embedded DuckDB columnar storage adapter.
    /// </summary>
    public class DuckDbSinkOptions
    {
        /// <summary>
        /// Gets or sets the path to the DuckDB database file (e.g. 'tum_siem_edge.duckdb' or ':memory:').
        /// </summary>
        public string DatabasePath { get; set; } = "tum_siem_edge.duckdb";

        /// <summary>
        /// Gets or sets the target table name.
        /// </summary>
        public string TableName { get; set; } = "tum_security_logs";

        /// <summary>
        /// Gets or sets the maximum batch size before triggering an automatic bulk flush.
        /// </summary>
        public int BatchSize { get; set; } = 2000;

        /// <summary>
        /// Gets or sets the maximum flush interval in milliseconds.
        /// </summary>
        public int FlushIntervalMs { get; set; } = 1000;

        /// <summary>
        /// Gets or sets a value indicating whether to automatically execute CREATE TABLE on startup.
        /// </summary>
        public bool AutoCreateSchema { get; set; } = true;

        /// <summary>
        /// Gets or sets a value indicating whether this sink is enabled.
        /// </summary>
        public bool IsEnabled { get; set; } = true;

        /// <summary>
        /// Gets or sets an optional delegate to execute DuckDB SQL commands via native driver or ADO.NET provider.
        /// When not set, the adapter writes SQL Appender script files or uses fallback persistence.
        /// </summary>
        public Func<string, CancellationToken, Task<int>>? CustomCommandExecutor { get; set; }
    }
}
