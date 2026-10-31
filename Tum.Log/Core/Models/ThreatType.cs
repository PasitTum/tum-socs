// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Tum.Trust.Security.Core.Models.Logging
{
    /// <summary>
    /// Types of security threats and web application attack vectors detected by TUMLog.
    /// </summary>
    public enum ThreatType
    {
        /// <summary>
        /// SQL Injection attempt (e.g. UNION SELECT, OR 1=1, DROP TABLE).
        /// </summary>
        SqlInjection = 1,

        /// <summary>
        /// Cross-Site Scripting (XSS) attempt (e.g. &lt;script&gt;, javascript:, onload=).
        /// </summary>
        CrossSiteScripting = 2,

        /// <summary>
        /// Directory or Path Traversal attempt (e.g. ../../etc/passwd, ..\windows\win.ini).
        /// </summary>
        PathTraversal = 3,

        /// <summary>
        /// Remote or OS Command Injection attempt (e.g. ; cat /etc/passwd, | dir, &amp; whoami).
        /// </summary>
        CommandInjection = 4,

        /// <summary>
        /// Brute-force authentication or credential stuffing attack.
        /// </summary>
        BruteForceAttempt = 5,

        /// <summary>
        /// Tampering of request payload, HTTP headers, or signatures.
        /// </summary>
        TamperingAttempt = 6
    }
}
