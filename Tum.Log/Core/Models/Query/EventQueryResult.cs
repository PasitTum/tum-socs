// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using System.Collections.Generic;
using Tum.Trust.Security.Core.Models.Logging;

namespace Tum.Trust.Security.Core.Models.Query
{
    /// <summary>
    /// Search query outcome containing matched events and execution diagnostics.
    /// </summary>
    public class EventQueryResult
    {
        /// <summary>
        /// Gets or sets the original query string evaluated.
        /// </summary>
        public string QueryExecuted { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the total number of entries evaluated during search.
        /// </summary>
        public long TotalScanned { get; set; }

        /// <summary>
        /// Gets or sets the count of matching entries before pagination limits.
        /// </summary>
        public long TotalMatched { get; set; }

        /// <summary>
        /// Gets or sets the execution duration of the query in milliseconds.
        /// </summary>
        public double ExecutionDurationMs { get; set; }

        /// <summary>
        /// Gets or sets the paginated list of matching log entries.
        /// </summary>
        public List<TumLogEntry> Items { get; set; } = new List<TumLogEntry>();

        /// <summary>
        /// Gets or sets the translated SQL WHERE clause representation for columnar database offloading.
        /// </summary>
        public string TranslatedSqlWhere { get; set; } = string.Empty;
    }
}
