// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Tum.Trust.Security.Core.Models.Risk
{
    /// <summary>
    /// Threat risk bands mapped from dynamic risk score (0-100).
    /// </summary>
    public enum RiskSeverityBand
    {
        /// <summary>
        /// Negligible or normal operational telemetry (0-19).
        /// </summary>
        Informational = 0,

        /// <summary>
        /// Low risk anomaly or minor policy violation (20-39).
        /// </summary>
        Low = 1,

        /// <summary>
        /// Medium risk indicator requiring investigation (40-69).
        /// </summary>
        Medium = 2,

        /// <summary>
        /// High risk security threat or confirmed attack vector (70-89).
        /// </summary>
        High = 3,

        /// <summary>
        /// Critical exploit, active breach, or massive data exfiltration (90-100).
        /// </summary>
        Critical = 4
    }
}
