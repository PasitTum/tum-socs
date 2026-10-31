// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Tum.Trust.Security.Core.Models.Logging;

namespace Tum.Trust.Security.Core.Interfaces.Logging
{
    /// <summary>
    /// Multi-destination sink dispatcher routing sanitized log entries to configured enterprise targets
    /// (Local WORM, Syslog RFC 5424, OpenSearch, AWS S3, Azure Blob, Kafka).
    /// </summary>
    public interface ILogSinkDispatcher
    {
        /// <summary>
        /// Dispatches a log entry to all active configured destination sinks asynchronously.
        /// </summary>
        /// <param name="entry">The log entry to send.</param>
        /// <param name="cancellationToken">A cancellation token.</param>
        /// <returns>A list of destination sinks that successfully received the entry.</returns>
        Task<List<StorageSinkType>> DispatchAsync(TumLogEntry entry, CancellationToken cancellationToken = default);
    }
}
