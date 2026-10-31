// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Tum.Trust.Security.Core.Models.Logging
{
    /// <summary>
    /// Categorizes application-layer events for granular filtering, indexing, and compliance routing.
    /// </summary>
    public enum LogCategory
    {
        /// <summary>
        /// General user activity and audit trail (e.g. login, logout, page view, profile update).
        /// </summary>
        AuditTrail = 1,

        /// <summary>
        /// Security events, attack detections, tampering attempts, or failed authentications.
        /// </summary>
        SecurityThreat = 2,

        /// <summary>
        /// Access, viewing, or exporting of Personal Identifiable Information (PII) under PDPA/GDPR scrutiny.
        /// </summary>
        PiiAccess = 3,

        /// <summary>
        /// Core business transactions (e.g. payment, checkout, e-KYC verification, contract signing).
        /// </summary>
        BusinessTransaction = 4,

        /// <summary>
        /// Technical diagnostics, performance measurements, error traces, and system telemetry.
        /// </summary>
        SystemDiagnostic = 5,

        /// <summary>
        /// Regulatory compliance events specifically designated for Thai Computer Crime Act Sec 26.
        /// </summary>
        LegalCompliance = 6
    }
}
