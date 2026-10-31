// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using System.Collections.Generic;
using Tum.Trust.Security.Core.Models.Logging;
using Tum.Trust.Security.Core.Models.Risk;
using Tum.Trust.Security.Core.Models.Sigma;

namespace Tum.Trust.Security.Core.Models.Alerts
{
    /// <summary>
    /// Security alert incident payload prepared for real-time dispatch across SecOps channels.
    /// </summary>
    public class AlertNotification
    {
        /// <summary>
        /// Unique alert identifier.
        /// </summary>
        public string AlertId { get; set; } = Guid.NewGuid().ToString("N");

        /// <summary>
        /// High-level alert headline.
        /// </summary>
        public string Title { get; set; } = string.Empty;

        /// <summary>
        /// Detailed description of the threat or incident.
        /// </summary>
        public string Description { get; set; } = string.Empty;

        /// <summary>
        /// Aggregate risk score (0-100).
        /// </summary>
        public double RiskScore { get; set; }

        /// <summary>
        /// Categorized severity band.
        /// </summary>
        public RiskSeverityBand SeverityBand { get; set; } = RiskSeverityBand.High;

        /// <summary>
        /// Timestamp of the security incident in UTC.
        /// </summary>
        public DateTimeOffset TimestampUtc { get; set; } = DateTimeOffset.UtcNow;

        /// <summary>
        /// Client IP initiating the activity.
        /// </summary>
        public string ClientIp { get; set; } = "127.0.0.1";

        /// <summary>
        /// Originating application name.
        /// </summary>
        public string ApplicationName { get; set; } = "TUM-OpenSIEM";

        /// <summary>
        /// Target environment ('Production', 'Staging', 'Development').
        /// </summary>
        public string Environment { get; set; } = "Production";

        /// <summary>
        /// Standard event action taxonomy (e.g. 'AUTH.BRUTE_FORCE').
        /// </summary>
        public string StandardAction { get; set; } = string.Empty;

        /// <summary>
        /// List of MITRE ATT&amp;CK techniques identified.
        /// </summary>
        public List<string> MitreTechniques { get; set; } = new List<string>();

        /// <summary>
        /// Sigma rules triggered.
        /// </summary>
        public List<SigmaMatchResult> MatchedRules { get; set; } = new List<SigmaMatchResult>();

        /// <summary>
        /// Diagnostic risk breakdown.
        /// </summary>
        public List<RiskFactor> RiskFactors { get; set; } = new List<RiskFactor>();

        /// <summary>
        /// Associated log entry.
        /// </summary>
        public TumLogEntry? LogEntry { get; set; }
    }
}
