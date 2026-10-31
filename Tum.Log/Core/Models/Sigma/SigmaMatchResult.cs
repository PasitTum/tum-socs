// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using System.Collections.Generic;

namespace Tum.Trust.Security.Core.Models.Sigma
{
    /// <summary>
    /// Represents the evaluation outcome when a log entry matches a Sigma rule.
    /// </summary>
    public class SigmaMatchResult
    {
        /// <summary>
        /// Gets or sets the ID of the matched rule.
        /// </summary>
        public string RuleId { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the title of the matched rule.
        /// </summary>
        public string RuleTitle { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the severity level of the matched rule.
        /// </summary>
        public SigmaRuleLevel Level { get; set; }

        /// <summary>
        /// Gets or sets the MITRE ATT&amp;CK techniques associated with this detection.
        /// </summary>
        public List<string> MitreTechniques { get; set; } = new List<string>();

        /// <summary>
        /// Gets or sets the matched log entry identifier.
        /// </summary>
        public string LogId { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the timestamp when the match occurred.
        /// </summary>
        public DateTimeOffset MatchedAtUtc { get; set; } = DateTimeOffset.UtcNow;
    }
}
