// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using Tum.Trust.Security.Core.Models.Logging;

namespace Tum.Trust.Security.Core.Models.Query
{
    /// <summary>
    /// Search query request parameters supporting Lucene-like field filters and full-text matching.
    /// </summary>
    public class EventQueryRequest
    {
        /// <summary>
        /// Gets or sets the query expression string (e.g. 'category:SecurityThreat AND severity:Critical', 'clientIp:10.0.0.1').
        /// </summary>
        public string Query { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the optional start timestamp filter in UTC.
        /// </summary>
        public DateTimeOffset? FromUtc { get; set; }

        /// <summary>
        /// Gets or sets the optional end timestamp filter in UTC.
        /// </summary>
        public DateTimeOffset? ToUtc { get; set; }

        /// <summary>
        /// Gets or sets the optional specific category filter.
        /// </summary>
        public LogCategory? Category { get; set; }

        /// <summary>
        /// Gets or sets the maximum number of results to retrieve (default: 100, max: 10,000).
        /// </summary>
        public int Limit { get; set; } = 100;

        /// <summary>
        /// Gets or sets the pagination offset.
        /// </summary>
        public int Offset { get; set; } = 0;
    }
}
