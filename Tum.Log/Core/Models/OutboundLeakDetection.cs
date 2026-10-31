// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;

namespace Tum.Trust.Security.Core.Models.Logging
{
    /// <summary>
    /// Represents an intercepted outbound data leakage event detected in an egress HTTP response.
    /// </summary>
    public class OutboundLeakDetection
    {
        /// <summary>
        /// Gets or sets the classification of the outbound leak.
        /// </summary>
        public OutboundLeakType LeakType { get; set; }

        /// <summary>
        /// Gets or sets the description of the matched leak pattern.
        /// </summary>
        public string MatchedPattern { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the original offending snippet before redaction.
        /// </summary>
        public string RawSnippet { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the safe replacement snippet delivered to the client.
        /// </summary>
        public string RedactedSnippet { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the severity of the prevented leak ('Medium', 'High', 'Critical').
        /// </summary>
        public string Severity { get; set; } = "High";

        /// <summary>
        /// Gets or sets the UTC timestamp when the leak was caught.
        /// </summary>
        public DateTimeOffset TimestampUtc { get; set; } = DateTimeOffset.UtcNow;
    }
}
