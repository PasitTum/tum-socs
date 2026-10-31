// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;

namespace Tum.Trust.Security.Core.Models.Logging
{
    /// <summary>
    /// Represents a cryptographic tamper-proof receipt verifying the integrity of a log entry
    /// and its position within the immutable SHA-256 Merkle chain under Thai Computer Crime Act Sec 26.
    /// </summary>
    public class TamperProofReceipt
    {
        /// <summary>
        /// Gets or sets the unique ID of the verified log entry.
        /// </summary>
        public string LogId { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the SHA-256 hash of this entry's sanitized content.
        /// </summary>
        public string EntryHashSha256 { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the SHA-256 hash of the immediately preceding log entry in the chain.
        /// </summary>
        public string PreviousEntryHashSha256 { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the Merkle root hash incorporating this entry and previous blocks.
        /// </summary>
        public string MerkleRootSha256 { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the Stratum 1 NTP reference time stamped at entry creation.
        /// </summary>
        public DateTimeOffset NtpTimestampUtc { get; set; } = DateTimeOffset.UtcNow;

        /// <summary>
        /// Gets or sets a value indicating whether the cryptographic hash chain has been verified as unbroken.
        /// </summary>
        public bool IsChainIntact { get; set; }

        /// <summary>
        /// Gets or sets the WORM (Write Once Read Many) retention expiry date (e.g. 90 days from timestamp).
        /// </summary>
        public DateTimeOffset WormRetentionExpiresUtc { get; set; }
    }
}
