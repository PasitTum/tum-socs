// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using System.Collections.Generic;

namespace Tum.Trust.Security.Core.Models.Logging
{
    /// <summary>
    /// Tracks an discovered API route or endpoint, its PII exposure profile, request frequency, and risk score.
    /// Provides enterprises with an automated data flow map of where sensitive data moves across the system.
    /// </summary>
    public class EndpointPiiProfile
    {
        /// <summary>
        /// Gets or sets the HTTP route template or path (e.g. '/api/v1/customers/kyc').
        /// </summary>
        public string RoutePath { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the HTTP method ('GET', 'POST', 'PUT', etc.).
        /// </summary>
        public string HttpMethod { get; set; } = "GET";

        /// <summary>
        /// Gets or sets the timestamp when this endpoint was first discovered.
        /// </summary>
        public DateTimeOffset FirstSeenUtc { get; set; } = DateTimeOffset.UtcNow;

        /// <summary>
        /// Gets or sets the timestamp of the most recent invocation.
        /// </summary>
        public DateTimeOffset LastAccessedUtc { get; set; } = DateTimeOffset.UtcNow;

        /// <summary>
        /// Gets or sets the total cumulative request count through this route.
        /// </summary>
        public long TotalInvocationCount { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether incoming requests to this endpoint carry PII.
        /// </summary>
        public bool InboundPiiDetected { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether outbound responses from this endpoint contain PII.
        /// </summary>
        public bool OutboundPiiDetected { get; set; }

        /// <summary>
        /// Gets or sets the distinct PII data types identified on this endpoint (e.g. ThaiNationalId, CreditCard).
        /// </summary>
        public HashSet<PiiType> ObservedPiiTypes { get; set; } = new HashSet<PiiType>();

        /// <summary>
        /// Gets or sets the cumulative security threat attempts targeted at this endpoint.
        /// </summary>
        public int ThreatAttemptsCount { get; set; }

        /// <summary>
        /// Gets the calculated risk level ('Low', 'Medium', 'High', 'Critical') based on PII density and threat activity.
        /// </summary>
        public string RiskLevel
        {
            get
            {
                if (ThreatAttemptsCount > 5 || (InboundPiiDetected && OutboundPiiDetected && ObservedPiiTypes.Count >= 2))
                {
                    return "Critical";
                }
                if (InboundPiiDetected || OutboundPiiDetected)
                {
                    return "High";
                }
                if (ThreatAttemptsCount > 0)
                {
                    return "Medium";
                }
                return "Low";
            }
        }
    }
}
