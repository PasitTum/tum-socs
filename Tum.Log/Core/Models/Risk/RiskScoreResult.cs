// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using System.Collections.Generic;

namespace Tum.Trust.Security.Core.Models.Risk
{
    /// <summary>
    /// Calculated dynamic risk score (0-100) with diagnostic breakdown of contributing threat factors.
    /// </summary>
    public class RiskScoreResult
    {
        /// <summary>
        /// Gets or sets the normalized risk score clamped to [0.0, 100.0].
        /// </summary>
        public double Score { get; set; }

        /// <summary>
        /// Gets or sets the calculated severity band.
        /// </summary>
        public RiskSeverityBand SeverityBand { get; set; } = RiskSeverityBand.Informational;

        /// <summary>
        /// Gets or sets the list of individual factors that contributed to this score.
        /// </summary>
        public List<RiskFactor> Factors { get; set; } = new List<RiskFactor>();

        /// <summary>
        /// Gets or sets the timestamp when the score was computed.
        /// </summary>
        public DateTimeOffset EvaluatedAtUtc { get; set; } = DateTimeOffset.UtcNow;

        /// <summary>
        /// Helper to determine whether this risk score breaches the alerting threshold.
        /// </summary>
        /// <param name="threshold">Minimum score requiring alert dispatch (e.g. 70.0).</param>
        public bool ShouldAlert(double threshold = 70.0) => Score >= threshold;
    }
}
