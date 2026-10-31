// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;

namespace Tum.Trust.Security.Core.Models.Logging
{
    /// <summary>
    /// Configuration for an external log destination sink (e.g. Syslog RFC 5424, OpenSearch, S3).
    /// </summary>
    public class LogDestinationConfig
    {
        /// <summary>
        /// Gets or sets the target sink type.
        /// </summary>
        public StorageSinkType SinkType { get; set; } = StorageSinkType.LocalWormFile;

        /// <summary>
        /// Gets or sets the target URI or network endpoint (e.g. 'syslog://siem.corp.internal:514' or 'https://opensearch:9200').
        /// </summary>
        public string EndpointUri { get; set; } = "local://tum_logs";

        /// <summary>
        /// Gets or sets the authentication token, API key, or credentials.
        /// </summary>
        public string? ApiKeyOrToken { get; set; }

        /// <summary>
        /// Gets or sets the target index name, bucket name, or Kafka topic.
        /// </summary>
        public string TargetName { get; set; } = "tumlog-audit-events";

        /// <summary>
        /// Gets or sets a value indicating whether this destination sink is actively enabled.
        /// </summary>
        public bool IsEnabled { get; set; } = true;

        /// <summary>
        /// Gets or sets the maximum batch size before flushing to this destination.
        /// </summary>
        public int BatchSize { get; set; } = 100;

        /// <summary>
        /// Gets or sets the maximum flush interval in milliseconds.
        /// </summary>
        public int FlushIntervalMs { get; set; } = 2000;
    }
}
