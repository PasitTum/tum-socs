// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Collections.Generic;
using Tum.Trust.Security.Core.Models.Logging;
using Tum.Trust.Security.Core.Models.Sigma;

namespace Tum.Trust.Security.Core.Interfaces.Logging
{
    /// <summary>
    /// Contract for the Native Sigma Rule Engine compiling open Sigma rules into in-memory Expression Trees.
    /// </summary>
    public interface ISigmaRuleEngine
    {
        /// <summary>
        /// Gets the total number of compiled rules currently active in memory.
        /// </summary>
        int ActiveRuleCount { get; }

        /// <summary>
        /// Registers and compiles a Sigma rule into high-performance in-memory delegates.
        /// </summary>
        /// <param name="rule">The Sigma rule.</param>
        void RegisterRule(SigmaRule rule);

        /// <summary>
        /// Registers a collection of Sigma rules.
        /// </summary>
        /// <param name="rules">Rules to register.</param>
        void RegisterRules(IEnumerable<SigmaRule> rules);

        /// <summary>
        /// Evaluates a log entry against all compiled Sigma rules in memory.
        /// </summary>
        /// <param name="entry">The log entry to evaluate.</param>
        /// <returns>List of matching rule results.</returns>
        IReadOnlyList<SigmaMatchResult> Evaluate(TumLogEntry entry);

        /// <summary>
        /// Clears all currently registered rules.
        /// </summary>
        void ClearRules();
    }
}
