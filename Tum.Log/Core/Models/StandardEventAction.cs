// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using System.Text.RegularExpressions;

namespace Tum.Trust.Security.Core.Models.Logging
{
    /// <summary>
    /// Standardized event naming taxonomy and action definitions conforming to ISO/IEC 27001 (A.12.4)
    /// and OWASP Logging Guidelines. Enforces structured 'NOUN.VERB' format with strict character length limits.
    /// </summary>
    public static class StandardEventAction
    {
        /// <summary>
        /// Default maximum allowed characters for an event name to ensure efficient SIEM indexing and display.
        /// </summary>
        public const int DefaultMaxEventNameLength = 32;

        /// <summary>Authentication login action event.</summary>
        public const string AuthLogin = "AUTH.LOGIN";

        /// <summary>Authentication logout action event.</summary>
        public const string AuthLogout = "AUTH.LOGOUT";

        /// <summary>Authentication failure action event.</summary>
        public const string AuthFailed = "AUTH.FAILED";

        /// <summary>Multi-factor authentication challenge action event.</summary>
        public const string AuthMfaChallenge = "AUTH.MFA_CHALLENGE";

        /// <summary>Data read or query action event (PDPA tracked).</summary>
        public const string DataRead = "DATA.READ";

        /// <summary>Data creation action event (PDPA tracked).</summary>
        public const string DataCreate = "DATA.CREATE";

        /// <summary>Data update or modify action event (PDPA tracked).</summary>
        public const string DataUpdate = "DATA.UPDATE";

        /// <summary>Data deletion action event (PDPA tracked).</summary>
        public const string DataDelete = "DATA.DELETE";

        /// <summary>Data export or download action event (PDPA tracked).</summary>
        public const string DataExport = "DATA.EXPORT";

        /// <summary>User privilege or role escalation change event (ISO 27001 A.12.4.3).</summary>
        public const string SecPrivilegeEscalate = "SEC.PRIVILEGE_CHANGE";

        /// <summary>Security policy or firewall rule modification event.</summary>
        public const string SecPolicyModify = "SEC.POLICY_MODIFY";

        /// <summary>Active threat or attack pattern intercepted event.</summary>
        public const string SecThreatDetected = "SEC.THREAT_DETECTED";

        /// <summary>Outbound sensitive data or PII leakage prevented event.</summary>
        public const string SecLeakPrevented = "SEC.LEAK_PREVENTED";

        /// <summary>System or server configuration change event.</summary>
        public const string SysConfigChange = "SYS.CONFIG_CHANGE";

        /// <summary>Core business or payment transaction event.</summary>
        public const string BizTransaction = "BIZ.TRANSACTION";

        private static readonly Regex ValidNamePattern = new(@"[^A-Z0-9_\.]", RegexOptions.Compiled);

        /// <summary>
        /// Normalizes an event name to uppercase standard dot notation and truncates to the maximum allowed length.
        /// </summary>
        /// <param name="rawEventName">The original event name provided by developer.</param>
        /// <param name="maxLength">The maximum character limit (default: 32).</param>
        /// <returns>A standardized, concise event name.</returns>
        public static string Normalize(string? rawEventName, int maxLength = DefaultMaxEventNameLength)
        {
            if (string.IsNullOrWhiteSpace(rawEventName))
            {
                return "GENERIC.EVENT";
            }

            string clean = rawEventName.Trim().ToUpperInvariant();
            clean = clean.Replace(" ", "_").Replace("-", "_");
            clean = ValidNamePattern.Replace(clean, string.Empty);

            if (clean.Length > maxLength)
            {
                clean = clean.Substring(0, maxLength).TrimEnd('.');
            }

            return string.IsNullOrEmpty(clean) ? "GENERIC.EVENT" : clean;
        }
    }
}
