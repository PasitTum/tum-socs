// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;

namespace Tum.Trust.Security.Core.Models.Logging
{
    /// <summary>
    /// Regulatory and legal compliance standards enforced by TUMLog.
    /// </summary>
    [Flags]
    public enum ComplianceStandard
    {
        /// <summary>
        /// None.
        /// </summary>
        None = 0,

        /// <summary>
        /// Thai Computer Crime Act B.E. 2560 Section 26 (Mandatory 90-day WORM immutable log with NTP time synchronization).
        /// </summary>
        ThaiComputerCrimeAct2560Sec26 = 1 << 0,

        /// <summary>
        /// Thai Personal Data Protection Act B.E. 2562 (PDPA) - Zero plaintext PII retention.
        /// </summary>
        ThaiPdpa = 1 << 1,

        /// <summary>
        /// European Union General Data Protection Regulation (GDPR) - Right to erasure and pseudo-anonymization.
        /// </summary>
        Gdpr = 1 << 2,

        /// <summary>
        /// ISO/IEC 27001 Information Security Management Standard.
        /// </summary>
        Iso27001 = 1 << 3,

        /// <summary>
        /// Payment Card Industry Data Security Standard (PCI-DSS) - Masking Primary Account Numbers (PAN).
        /// </summary>
        PciDss = 1 << 4
    }
}
