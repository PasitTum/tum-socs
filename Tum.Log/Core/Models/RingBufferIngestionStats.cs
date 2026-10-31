// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;

namespace Tum.Trust.Security.Core.Models.Logging
{
    /// <summary>
    /// Telemetry and throughput statistics for the TUM-OpenSIEM RingBuffer Ingestion Engine.
    /// </summary>
    public class RingBufferIngestionStats
    {
        /// <summary>
        /// Gets or sets the total number of events successfully enqueued.
        /// </summary>
        public long TotalEnqueued { get; set; }

        /// <summary>
        /// Gets or sets the total number of events successfully flushed/persisted to sinks.
        /// </summary>
        public long TotalProcessed { get; set; }

        /// <summary>
        /// Gets or sets the count of events dropped due to backpressure queue overflow.
        /// </summary>
        public long TotalDropped { get; set; }

        /// <summary>
        /// Gets or sets current unconsumed queue depth.
        /// </summary>
        public int CurrentQueueDepth { get; set; }

        /// <summary>
        /// Gets or sets the buffer capacity limit.
        /// </summary>
        public int BufferCapacity { get; set; }

        /// <summary>
        /// Gets or sets current observed Events Per Second (EPS).
        /// </summary>
        public double EventsPerSecond { get; set; }

        /// <summary>
        /// Gets or sets the duration of the measurement window.
        /// </summary>
        public TimeSpan ElapsedTime { get; set; }
    }
}
