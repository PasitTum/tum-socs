// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Tum.Trust.Security.Core.Models.Logging;

namespace Tum.Trust.Security.Core.Interfaces.Logging
{
    /// <summary>
    /// The primary sovereign logging and compliance engine coordinating PII sanitization,
    /// threat detection, and tamper-proof WORM persistence.
    /// </summary>
    public interface ITumLogEngine
    {
        /// <summary>
        /// Ingests a pre-constructed log entry, automatically executing PII masking, threat detection,
        /// and cryptographic hash chaining before persisting.
        /// </summary>
        /// <param name="entry">The log entry to process.</param>
        /// <param name="cancellationToken">A cancellation token.</param>
        /// <returns>The processed and persisted log entry with tamper-proof hashes populated.</returns>
        Task<TumLogEntry> LogAsync(TumLogEntry entry, CancellationToken cancellationToken = default);

        /// <summary>
        /// High-level fluent ingestion method for application events.
        /// </summary>
        /// <param name="eventName">Descriptive event name (e.g. 'User.Login', 'Payment.Completed').</param>
        /// <param name="category">The functional log category.</param>
        /// <param name="payload">The text or JSON payload.</param>
        /// <param name="userId">Optional user/subject ID.</param>
        /// <param name="clientIp">Client IP address.</param>
        /// <param name="severity">Severity level (default: 'Information').</param>
        /// <param name="cancellationToken">A cancellation token.</param>
        /// <returns>The persisted log entry.</returns>
        Task<TumLogEntry> LogEventAsync(
            string eventName,
            LogCategory category,
            string payload,
            string? userId = null,
            string? clientIp = null,
            string severity = "Information",
            CancellationToken cancellationToken = default);

        /// <summary>
        /// Traverses and validates the integrity of the active cryptographic Merkle chain.
        /// </summary>
        /// <param name="cancellationToken">A cancellation token.</param>
        /// <returns><c>true</c> if valid; otherwise <c>false</c>.</returns>
        Task<bool> VerifyIntegrityAsync(CancellationToken cancellationToken = default);

        /// <summary>
        /// Retrieves the most recent log entries with optional category filtering.
        /// </summary>
        /// <param name="count">Number of entries to fetch.</param>
        /// <param name="filterCategory">Optional category filter.</param>
        /// <param name="cancellationToken">A cancellation token.</param>
        /// <returns>Read-only list of log entries.</returns>
        Task<IReadOnlyList<TumLogEntry>> GetLogsAsync(int count = 100, LogCategory? filterCategory = null, CancellationToken cancellationToken = default);

        /// <summary>
        /// Gets the enterprise endpoint and PII registry cataloging discovered routes.
        /// </summary>
        IEndpointRegistry EndpointRegistry { get; }
    }
}
