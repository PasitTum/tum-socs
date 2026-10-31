// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using System.Collections.Generic;

namespace Tum.Trust.Security.Core.Models.Sigma
{
    /// <summary>
    /// Log source specification for Sigma rules.
    /// </summary>
    public class SigmaLogSource
    {
        /// <summary>
        /// Gets or sets the general log category (e.g. 'webserver', 'firewall', 'process_creation').
        /// </summary>
        public string? Category { get; set; }

        /// <summary>
        /// Gets or sets the target software product (e.g. 'windows', 'linux', 'apache', 'tumlog').
        /// </summary>
        public string? Product { get; set; }

        /// <summary>
        /// Gets or sets the service or subsystem (e.g. 'auth', 'syslog', 'sshd').
        /// </summary>
        public string? Service { get; set; }
    }

    /// <summary>
    /// Open Sigma Rule representation compatible with SigmaHQ specifications.
    /// Used for in-memory threat detection compiling into high-speed C# Expression Trees.
    /// </summary>
    public class SigmaRule
    {
        /// <summary>
        /// Gets or sets the unique UUID or rule identifier.
        /// </summary>
        public string Id { get; set; } = Guid.NewGuid().ToString("D");

        /// <summary>
        /// Gets or sets the human-readable rule title.
        /// </summary>
        public string Title { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the description of the threat or technique detected.
        /// </summary>
        public string Description { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the maturity status ('experimental', 'test', 'stable').
        /// </summary>
        public string Status { get; set; } = "stable";

        /// <summary>
        /// Gets or sets the severity level (Low, Medium, High, Critical).
        /// </summary>
        public SigmaRuleLevel Level { get; set; } = SigmaRuleLevel.Medium;

        /// <summary>
        /// Gets or sets the target log source.
        /// </summary>
        public SigmaLogSource LogSource { get; set; } = new SigmaLogSource();

        /// <summary>
        /// Gets or sets the list of classification tags (e.g. 'attack.t1059.001', 'attack.execution').
        /// </summary>
        public List<string> Tags { get; set; } = new List<string>();

        /// <summary>
        /// Gets or sets the detection field selectors mapping selector name to criteria.
        /// e.g. "selection" -> { "EventName": ["AUTH.LOGIN"], "PayloadSanitized|contains": ["UNION SELECT"] }
        /// </summary>
        public Dictionary<string, Dictionary<string, List<string>>> Selections { get; set; } =
            new Dictionary<string, Dictionary<string, List<string>>>(StringComparer.OrdinalIgnoreCase);

        /// <summary>
        /// Gets or sets the boolean condition expression (e.g. 'selection', 'selection and not filter').
        /// </summary>
        public string Condition { get; set; } = "selection";

        /// <summary>
        /// Gets or sets the known benign activities that might trigger false positives.
        /// </summary>
        public List<string> FalsePositives { get; set; } = new List<string>();

        /// <summary>
        /// Extracts all MITRE ATT&amp;CK technique IDs tagged on this rule (e.g. 'T1059.001').
        /// </summary>
        public List<string> GetMitreTechniques()
        {
            var techniques = new List<string>();
            foreach (var tag in Tags)
            {
                if (tag.StartsWith("attack.t", StringComparison.OrdinalIgnoreCase))
                {
                    techniques.Add(tag.Substring("attack.".Length).ToUpperInvariant());
                }
            }
            return techniques;
        }
    }
}
