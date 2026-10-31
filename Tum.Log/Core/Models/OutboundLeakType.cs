// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Tum.Trust.Security.Core.Models.Logging
{
    /// <summary>
    /// Types of sensitive data leaks intercepted on outbound HTTP response bodies.
    /// </summary>
    public enum OutboundLeakType
    {
        /// <summary>
        /// Accidental outbound leak of Personal Identifiable Information (Citizen ID, Passport, PAN).
        /// </summary>
        PiiLeakagePrevented = 1,

        /// <summary>
        /// Internal database syntax error leaking database schema, table names, or SQL dialects.
        /// </summary>
        DatabaseErrorSuppressed = 2,

        /// <summary>
        /// Detailed application stack trace or exception dump leaking source paths and versions.
        /// </summary>
        StackTraceRedacted = 3,

        /// <summary>
        /// Server secret token, private key, or internal bearer token mistakenly returned in JSON response.
        /// </summary>
        SecretTokenExposed = 4
    }
}
