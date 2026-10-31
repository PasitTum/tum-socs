// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Collections.Generic;
using Tum.Trust.Security.Core.Models.Logging;

namespace Tum.Trust.Security.Core.Interfaces.Logging
{
    /// <summary>
    /// Bidirectional inspection engine analyzing egress HTTP responses to prevent accidental PII leakage,
    /// database error disclosure, and stack trace exfiltration to clients.
    /// </summary>
    public interface IOutboundLeakDetector
    {
        /// <summary>
        /// Scans an egress response body, detects sensitive leaks, sanitizes the content, and returns detection details.
        /// </summary>
        /// <param name="responseBody">The HTTP response body string.</param>
        /// <param name="statusCode">The HTTP status code.</param>
        /// <returns>A tuple of the sanitized response body and the list of intercepted leaks.</returns>
        (string SanitizedBody, List<OutboundLeakDetection> Leaks) InspectAndSanitizeOutbound(string responseBody, int statusCode);
    }
}
