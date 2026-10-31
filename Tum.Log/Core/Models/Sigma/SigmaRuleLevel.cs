// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Tum.Trust.Security.Core.Models.Sigma
{
    /// <summary>
    /// Standard severity levels for SigmaHQ rules.
    /// </summary>
    public enum SigmaRuleLevel
    {
        /// <summary>
        /// Informational / Low severity event.
        /// </summary>
        Low = 1,

        /// <summary>
        /// Medium severity event.
        /// </summary>
        Medium = 2,

        /// <summary>
        /// High severity security threat.
        /// </summary>
        High = 3,

        /// <summary>
        /// Critical exploit or active incident.
        /// </summary>
        Critical = 4
    }
}
