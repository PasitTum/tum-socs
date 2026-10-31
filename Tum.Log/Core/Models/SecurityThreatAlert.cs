// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;

namespace Tum.Trust.Security.Core.Models.Logging
{
    /// <summary>
    /// Represents an active security threat or malicious attack pattern detected in an incoming request.
    /// </summary>
    public class SecurityThreatAlert
    {
        /// <summary>
        /// Gets or sets the classification of the threat.
        /// </summary>
        public ThreatType ThreatType { get; set; }

        /// <summary>
        /// Gets or sets the threat severity level ('Low', 'Medium', 'High', 'Critical').
        /// </summary>
        public string Severity { get; set; } = "High";

        /// <summary>
        /// Gets or sets the signature or heuristic pattern that matched.
        /// </summary>
        public string MatchedPattern { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the offending input snippet extracted from path, query, or body.
        /// </summary>
        public string SuspiciousSnippet { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the mitigation action taken (e.g. 'LoggedAndSanitized', 'Blocked403', 'RateLimited').
        /// </summary>
        public string MitigationAction { get; set; } = "LoggedAndSanitized";

        /// <summary>
        /// Gets or sets the client IP address initiating the attack.
        /// </summary>
        public string SourceIp { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the timestamp of the threat detection in UTC.
        /// </summary>
        public DateTimeOffset TimestampUtc { get; set; } = DateTimeOffset.UtcNow;
    }
}
