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
    /// Storage engine for immutable, tamper-evident log records chained via SHA-256 Merkle proofs,
    /// enforcing 90-day WORM retention under Thai Computer Crime Act B.E. 2560 Section 26.
    /// </summary>
    public interface ITamperProofLogStorage
    {
        /// <summary>
        /// Atomically appends a log entry to the immutable cryptographic chain and returns a verification receipt.
        /// </summary>
        /// <param name="entry">The sanitized log entry to persist.</param>
        /// <param name="cancellationToken">A cancellation token.</param>
        /// <returns>A receipt containing the entry hash, previous hash, and Merkle root.</returns>
        Task<TamperProofReceipt> AppendEntryAsync(TumLogEntry entry, CancellationToken cancellationToken = default);

        /// <summary>
        /// Traverses the entire recorded log chain from genesis to head, verifying that no entries
        /// have been altered, removed, or inserted out of order.
        /// </summary>
        /// <param name="cancellationToken">A cancellation token.</param>
        /// <returns><c>true</c> if the entire cryptographic chain is unbroken; otherwise <c>false</c>.</returns>
        Task<bool> VerifyChainIntegrityAsync(CancellationToken cancellationToken = default);

        /// <summary>
        /// Retrieves the most recent log entries up to the specified limit.
        /// </summary>
        /// <param name="count">Maximum entries to fetch.</param>
        /// <param name="cancellationToken">A cancellation token.</param>
        /// <returns>List of recent log entries.</returns>
        Task<IReadOnlyList<TumLogEntry>> GetRecentEntriesAsync(int count = 100, CancellationToken cancellationToken = default);

        /// <summary>
        /// Generates a standardized audit report export for regulatory submission to the Thai Ministry of Digital Economy and Society (MDES).
        /// </summary>
        /// <param name="fromUtc">Start timestamp in UTC.</param>
        /// <param name="toUtc">End timestamp in UTC.</param>
        /// <param name="cancellationToken">A cancellation token.</param>
        /// <returns>Formatted JSON or markdown compliance audit bundle with Merkle root verification.</returns>
        Task<string> ExportComplianceAuditLogAsync(DateTimeOffset fromUtc, DateTimeOffset toUtc, CancellationToken cancellationToken = default);
    }
}
