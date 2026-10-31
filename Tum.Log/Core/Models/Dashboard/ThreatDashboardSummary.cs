// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using System.Collections.Generic;

namespace Tum.Trust.Security.Core.Models.Dashboard
{
    /// <summary>
    /// Consolidated SIEM telemetry metrics for the unified web threat dashboard.
    /// </summary>
    public class ThreatDashboardSummary
    {
        public long TotalEventsIngested { get; set; }
        public double CurrentEventsPerSecond { get; set; }
        public int CriticalAlertsCount { get; set; }
        public int HighAlertsCount { get; set; }
        public int MediumAlertsCount { get; set; }
        public int LowAlertsCount { get; set; }
        public int ActiveSigmaRulesCount { get; set; }
        public int TotalPiiRedacted { get; set; }
        public bool ChainIntegrityVerified { get; set; } = true;
        public string GlobalMerkleRoot { get; set; } = string.Empty;
        public Dictionary<string, int> TopAttackerIps { get; set; } = new Dictionary<string, int>();
        public Dictionary<string, int> TopAttackedEndpoints { get; set; } = new Dictionary<string, int>();
        public Dictionary<string, int> MitreTechniquesSummary { get; set; } = new Dictionary<string, int>();
        public DateTimeOffset LastUpdatedUtc { get; set; } = DateTimeOffset.UtcNow;
    }
}
