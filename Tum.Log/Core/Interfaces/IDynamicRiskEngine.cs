// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Collections.Generic;
using Tum.Trust.Security.Core.Models.Logging;
using Tum.Trust.Security.Core.Models.Risk;
using Tum.Trust.Security.Core.Models.Sigma;

namespace Tum.Trust.Security.Core.Interfaces.Logging
{
    /// <summary>
    /// Contract for the dynamic risk scoring engine calculating contextual threat scores (0-100).
    /// </summary>
    public interface IDynamicRiskEngine
    {
        /// <summary>
        /// Evaluates a log entry and optional Sigma matches, calculating a continuous risk score (0-100).
        /// </summary>
        /// <param name="entry">The log entry under inspection.</param>
        /// <param name="sigmaMatches">Optional list of triggered Sigma rule matches.</param>
        /// <returns>Risk score evaluation result.</returns>
        RiskScoreResult EvaluateRisk(TumLogEntry entry, IReadOnlyList<SigmaMatchResult>? sigmaMatches = null);
    }
}
