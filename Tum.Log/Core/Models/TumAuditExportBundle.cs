// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using System.Collections.Generic;

namespace Tum.Trust.Security.Core.Models.Logging
{
    /// <summary>
    /// Cryptographic compliance audit export bundle verifying WORM chain of custody under Thai CCA 2560 Sec 26.
    /// </summary>
    public class TumAuditExportBundle
    {
        /// <summary>
        /// Gets or sets the audit certification identifier.
        /// </summary>
        public string AuditCertification { get; set; } = "TUM-TRUST-SECURITY-COMPLIANCE-CCA2560-SEC26";

        /// <summary>
        /// Gets or sets the compliance standard description.
        /// </summary>
        public string ComplianceStandard { get; set; } = "Thai Computer Crime Act B.E. 2560 Section 26 & PDPA B.E. 2562";

        /// <summary>
        /// Gets or sets the generation timestamp in UTC.
        /// </summary>
        public DateTimeOffset GeneratedUtc { get; set; } = DateTimeOffset.UtcNow;

        /// <summary>
        /// Gets or sets the NTP server host used for time synchronization.
        /// </summary>
        public string NtpSynchronizedWith { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the count of audited log entries.
        /// </summary>
        public int TotalEntriesAudited { get; set; }

        /// <summary>
        /// Gets or sets the latest chain head SHA-256 hash.
        /// </summary>
        public string ChainHeadHash { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the global Merkle root hash.
        /// </summary>
        public string GlobalMerkleRoot { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets a value indicating whether chain integrity was verified.
        /// </summary>
        public bool ChainIntegrityVerified { get; set; } = true;

        /// <summary>
        /// Gets or sets the audited log entries.
        /// </summary>
        public List<TumLogEntry> Entries { get; set; } = new List<TumLogEntry>();
    }
}
