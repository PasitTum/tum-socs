// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using Tum.Trust.Security.Core.Interfaces.Logging;
using Tum.Trust.Security.Core.Models.Logging;

namespace Tum.Trust.Security.Infrastructure.Logging
{
    /// <summary>
    /// Implements bidirectional outbound HTTP response inspection to prevent accidental data exfiltration,
    /// sensitive PII exposure, database error leaking, and stack trace dumps.
    /// </summary>
    public class OutboundLeakDetector : IOutboundLeakDetector
    {
        private readonly ITumPiiSanitizer _piiSanitizer;
        private readonly TumLogOptions _options;

        private static readonly Regex DatabaseErrorRegex = new(
            @"(?i)(?:Microsoft OLE DB Provider|SQL Server Native Client|syntax error at or near|ORA-\d{5}|PostgreSQL query failed|SQLiteException|MySqlException|Unclosed quotation mark after the character string|com\.mysql\.jdbc\.exceptions)",
            RegexOptions.Compiled);

        private static readonly Regex StackTraceRegex = new(
            @"(?i)(?:at\s+[a-zA-Z0-9_\.]+\([a-zA-Z0-9_\.\s,:]*\)\s+in\s+[a-zA-Z]:\\|Traceback \(most recent call last\):|NullReferenceException:|ArgumentNullException:|System\.Exception:)",
            RegexOptions.Compiled);

        private static readonly Regex PrivateKeyRegex = new(
            @"-----BEGIN (?:RSA )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA )?PRIVATE KEY-----",
            RegexOptions.Compiled);

        /// <summary>
        /// Initializes a new instance of the <see cref="OutboundLeakDetector"/> class.
        /// </summary>
        /// <param name="piiSanitizer">PII sanitizer instance.</param>
        /// <param name="options">Options instance.</param>
        public OutboundLeakDetector(ITumPiiSanitizer? piiSanitizer = null, TumLogOptions? options = null)
        {
            _options = options ?? new TumLogOptions();
            _piiSanitizer = piiSanitizer ?? new TumPiiSanitizer();
        }

        /// <inheritdoc />
        public (string SanitizedBody, List<OutboundLeakDetection> Leaks) InspectAndSanitizeOutbound(string responseBody, int statusCode)
        {
            var leaks = new List<OutboundLeakDetection>();
            if (string.IsNullOrEmpty(responseBody) || !_options.ScanOutboundResponses)
            {
                return (responseBody ?? string.Empty, leaks);
            }

            string sanitized = responseBody;

            // 1. Private Key Exfiltration Prevention
            sanitized = PrivateKeyRegex.Replace(sanitized, match =>
            {
                leaks.Add(new OutboundLeakDetection
                {
                    LeakType = OutboundLeakType.SecretTokenExposed,
                    MatchedPattern = "Cryptographic Private Key block detected in response body",
                    RawSnippet = "-----BEGIN PRIVATE KEY...[SNIPPED]",
                    RedactedSnippet = "[SEC_BLOCKED: Cryptographic Private Key exfiltration prevented]",
                    Severity = "Critical",
                    TimestampUtc = DateTimeOffset.UtcNow
                });
                return "[SEC_BLOCKED: Cryptographic Private Key exfiltration prevented]";
            });

            // 2. Database Syntax Error Suppression
            if (_options.MaskOutboundStackTraces)
            {
                sanitized = DatabaseErrorRegex.Replace(sanitized, match =>
                {
                    leaks.Add(new OutboundLeakDetection
                    {
                        LeakType = OutboundLeakType.DatabaseErrorSuppressed,
                        MatchedPattern = "Database dialect syntax error disclosure intercepted",
                        RawSnippet = match.Value,
                        RedactedSnippet = "[SEC_SUPPRESSED: Database internal error detail concealed]",
                        Severity = "High",
                        TimestampUtc = DateTimeOffset.UtcNow
                    });
                    return "[SEC_SUPPRESSED: Database internal error detail concealed]";
                });

                // 3. Stack Trace Redaction
                sanitized = StackTraceRegex.Replace(sanitized, match =>
                {
                    leaks.Add(new OutboundLeakDetection
                    {
                        LeakType = OutboundLeakType.StackTraceRedacted,
                        MatchedPattern = "Application exception stack trace dump intercepted",
                        RawSnippet = match.Value,
                        RedactedSnippet = "[SEC_SUPPRESSED: Internal application stack trace concealed]",
                        Severity = "Medium",
                        TimestampUtc = DateTimeOffset.UtcNow
                    });
                    return "[SEC_SUPPRESSED: Internal application stack trace concealed]";
                });
            }

            // 4. Outbound PII Sanitization (e.g. accidental Citizen ID / Credit Card return)
            if (_options.EnableAutoPiiMasking)
            {
                var (piiSanitized, piiDetections) = _piiSanitizer.SanitizeText(sanitized);
                if (piiDetections.Count > 0)
                {
                    sanitized = piiSanitized;
                    foreach (var d in piiDetections)
                    {
                        leaks.Add(new OutboundLeakDetection
                        {
                            LeakType = OutboundLeakType.PiiLeakagePrevented,
                            MatchedPattern = $"Outbound PII {d.Type} leakage intercepted",
                            RawSnippet = d.RawSnippet,
                            RedactedSnippet = d.MaskedSnippet,
                            Severity = "High",
                            TimestampUtc = DateTimeOffset.UtcNow
                        });
                    }
                }
            }

            return (sanitized, leaks);
        }
    }
}
