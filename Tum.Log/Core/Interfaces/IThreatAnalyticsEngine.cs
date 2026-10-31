// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Tum.Trust.Security.Core.Models.Dashboard;
using Tum.Trust.Security.Core.Models.Logging;
using Tum.Trust.Security.Core.Models.Sigma;

namespace Tum.Trust.Security.Core.Interfaces.Logging
{
    /// <summary>
    /// Contract for aggregating threat telemetry, constructing live attack graphs,
    /// and generating automated compliance posture audits.
    /// </summary>
    public interface IThreatAnalyticsEngine
    {
        /// <summary>
        /// Ingests a processed log entry and its associated Sigma detections into the analytical model.
        /// </summary>
        void RecordEvent(TumLogEntry entry, IReadOnlyList<SigmaMatchResult>? matches = null);

        /// <summary>
        /// Generates real-time SIEM dashboard metrics.
        /// </summary>
        ThreatDashboardSummary GetDashboardSummary();

        /// <summary>
        /// Builds the live correlated attack graph for WebGL/Canvas rendering.
        /// </summary>
        AttackGraphData GetAttackGraph(int maxNodes = 50);

        /// <summary>
        /// Compiles the formal compliance audit report verifying legal standards.
        /// </summary>
        Task<ComplianceAuditSummary> GenerateComplianceAuditAsync(CancellationToken cancellationToken = default);
    }
}
