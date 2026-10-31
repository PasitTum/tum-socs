// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Collections.Generic;
using Tum.Trust.Security.Core.Models.Logging;

namespace Tum.Trust.Security.Core.Interfaces.Logging
{
    /// <summary>
    /// Real-time heuristic and signature threat detection engine for application-layer payloads and HTTP requests.
    /// </summary>
    public interface ITumThreatDetector
    {
        /// <summary>
        /// Inspects a raw string payload for attack signatures (SQLi, XSS, Path Traversal, Command Injection).
        /// </summary>
        /// <param name="payload">The text or body payload to analyze.</param>
        /// <param name="sourceIp">The source IP address of the requester.</param>
        /// <returns>A list of detected threat alerts, or an empty list if clean.</returns>
        List<SecurityThreatAlert> InspectPayload(string payload, string sourceIp = "127.0.0.1");

        /// <summary>
        /// Inspects an incoming HTTP request across path, query parameters, headers, and body for attack vectors.
        /// </summary>
        /// <param name="path">The request URL path.</param>
        /// <param name="method">The HTTP method.</param>
        /// <param name="queryString">The query string component.</param>
        /// <param name="body">The request body content.</param>
        /// <param name="sourceIp">The source IP address.</param>
        /// <returns>A list of detected threat alerts.</returns>
        List<SecurityThreatAlert> InspectRequest(string? path, string? method, string? queryString, string? body, string sourceIp = "127.0.0.1");
    }
}
