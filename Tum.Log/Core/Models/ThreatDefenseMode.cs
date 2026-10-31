// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Tum.Trust.Security.Core.Models.Logging
{
    /// <summary>
    /// Operating modes for real-time security threat detection and active defense.
    /// Allows enterprises to balance smooth non-blocking execution against strict blocking policies.
    /// </summary>
    public enum ThreatDefenseMode
    {
        /// <summary>
        /// Smooth / Non-blocking mode (Recommended Default): Inspects, sanitizes PII, records threats into the WORM audit trail,
        /// and alerts security teams without intercepting or disrupting client traffic.
        /// </summary>
        AuditOnly = 1,

        /// <summary>
        /// Active Enforcement mode: Blocks high and critical severity attack patterns (SQLi, XSS, Path Traversal)
        /// with an HTTP 403 Forbidden response and an incident tracking reference ID.
        /// </summary>
        ActiveBlock = 2,

        /// <summary>
        /// Passive observation mode: Incurs minimal processing overhead for extreme high-throughput services.
        /// </summary>
        Disabled = 3
    }
}
