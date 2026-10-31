// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Tum.Trust.Security.Core.Models.Risk
{
    /// <summary>
    /// Represents a single contributing factor to the aggregate dynamic risk score.
    /// </summary>
    public class RiskFactor
    {
        /// <summary>
        /// Gets or sets the name or category of the risk factor (e.g. 'SigmaRuleMatch', 'PiiExposure', 'InboundThreat').
        /// </summary>
        public string FactorName { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the human-readable explanation of why this risk was applied.
        /// </summary>
        public string Description { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the numerical risk score contributed by this factor.
        /// </summary>
        public double ContributedScore { get; set; }

        /// <summary>
        /// Gets or sets the weight multiplier applied.
        /// </summary>
        public double Weight { get; set; } = 1.0;
    }
}
