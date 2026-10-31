// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using System.Threading;
using System.Threading.Tasks;
using Tum.Trust.Security.Core.Models.Logging;

namespace Tum.Trust.Security.Core.Interfaces.Logging
{
    /// <summary>
    /// Contract for the high-throughput, non-blocking RingBuffer Ingestion Engine powering TUM-OpenSIEM.
    /// Engineered to absorb bursty log streams exceeding 50,000 EPS per core.
    /// </summary>
    public interface ITumRingBufferIngestor : IAsyncDisposable, IDisposable
    {
        /// <summary>
        /// Attempts to immediately enqueue a log entry into the ring buffer without blocking.
        /// </summary>
        /// <param name="entry">The log entry.</param>
        /// <returns>True if enqueued successfully; false if buffer is full.</returns>
        bool TryEnqueue(TumLogEntry entry);

        /// <summary>
        /// Asynchronously enqueues a log entry, awaiting buffer slot availability if under backpressure.
        /// </summary>
        /// <param name="entry">The log entry.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        ValueTask<bool> EnqueueAsync(TumLogEntry entry, CancellationToken cancellationToken = default);

        /// <summary>
        /// Flushes all pending buffer entries to underlying sinks.
        /// </summary>
        /// <param name="cancellationToken">Cancellation token.</param>
        Task FlushAsync(CancellationToken cancellationToken = default);

        /// <summary>
        /// Retrieves real-time throughput metrics and queue status.
        /// </summary>
        RingBufferIngestionStats GetStats();

        /// <summary>
        /// Gets the current number of pending items in the ring buffer.
        /// </summary>
        int CurrentQueueDepth { get; }
    }
}
