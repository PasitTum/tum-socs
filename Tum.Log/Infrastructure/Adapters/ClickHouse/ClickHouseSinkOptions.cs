// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net.Http;

namespace Tum.Trust.Security.Infrastructure.Adapters.ClickHouse
{
    /// <summary>
    /// Configuration options for the high-throughput ClickHouse columnar storage adapter.
    /// </summary>
    public class ClickHouseSinkOptions
    {
        /// <summary>
        /// Gets or sets the ClickHouse HTTP interface URI (e.g. 'http://localhost:8123' or 'https://clickhouse.internal:8443').
        /// </summary>
        public string EndpointUri { get; set; } = "http://localhost:8123";

        /// <summary>
        /// Gets or sets the target database name.
        /// </summary>
        public string Database { get; set; } = "tum_siem";

        /// <summary>
        /// Gets or sets the target table name.
        /// </summary>
        public string TableName { get; set; } = "tum_security_logs";

        /// <summary>
        /// Gets or sets the authentication username.
        /// </summary>
        public string? Username { get; set; }

        /// <summary>
        /// Gets or sets the authentication password.
        /// </summary>
        public string? Password { get; set; }

        /// <summary>
        /// Gets or sets the maximum batch size before triggering an automatic bulk flush.
        /// </summary>
        public int BatchSize { get; set; } = 5000;

        /// <summary>
        /// Gets or sets the maximum flush interval in milliseconds.
        /// </summary>
        public int FlushIntervalMs { get; set; } = 1000;

        /// <summary>
        /// Gets or sets a value indicating whether to automatically execute CREATE DATABASE and CREATE TABLE on startup.
        /// </summary>
        public bool AutoCreateSchema { get; set; } = true;

        /// <summary>
        /// Gets or sets a value indicating whether this sink is enabled.
        /// </summary>
        public bool IsEnabled { get; set; } = true;

        /// <summary>
        /// Gets or sets an optional custom HttpMessageHandler for mock/in-memory testing or specialized connection pooling.
        /// </summary>
        public HttpMessageHandler? CustomHttpMessageHandler { get; set; }
    }
}
