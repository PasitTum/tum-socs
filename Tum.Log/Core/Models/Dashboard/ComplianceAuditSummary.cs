// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;

namespace Tum.Trust.Security.Core.Models.Dashboard
{
    /// <summary>
    /// Regulatory and legal compliance posture report verifying Thai Computer Crime Act Sec 26, PDPA, and ISO 27001.
    /// </summary>
    public class ComplianceAuditSummary
    {
        public string CertificationId { get; set; } = "TUM-TRUST-SECURITY-COMPLIANCE-CCA2560-SEC26";
        public string StandardName { get; set; } = "Thai Computer Crime Act B.E. 2560 Section 26 & PDPA B.E. 2562 & ISO/IEC 27001 (A.12.4)";
        public bool ComputerCrimeActSec26Compliant { get; set; } = true;
        public bool ThaiPdpaCompliant { get; set; } = true;
        public bool Iso27001Compliant { get; set; } = true;
        public bool NtpStratum1Synchronized { get; set; } = true;
        public string NtpServerHost { get; set; } = "time.navy.mi.th";
        public string ImmutableWormChainHead { get; set; } = string.Empty;
        public string GlobalMerkleRoot { get; set; } = string.Empty;
        public int WormRetentionDaysEnforced { get; set; } = 90;
        public int TotalAuditedEvents { get; set; }
        public int TotalPiiRedactedElements { get; set; }
        public bool ChainIntegrityCryptographicallyVerified { get; set; } = true;
        public DateTimeOffset ReportGeneratedUtc { get; set; } = DateTimeOffset.UtcNow;
    }
}
