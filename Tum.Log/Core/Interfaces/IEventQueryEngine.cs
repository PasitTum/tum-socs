// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Tum.Trust.Security.Core.Models.Logging;
using Tum.Trust.Security.Core.Models.Query;

namespace Tum.Trust.Security.Core.Interfaces.Logging
{
    /// <summary>
    /// Contract for the high-speed search and query explorer engine supporting Lucene/SQL-like syntax.
    /// </summary>
    public interface IEventQueryEngine
    {
        /// <summary>
        /// Compiles a Lucene-like query expression into an in-memory predicate.
        /// </summary>
        /// <param name="query">The query string (e.g. 'category:SecurityThreat AND severity:Critical').</param>
        /// <returns>Compiled predicate function.</returns>
        Func<TumLogEntry, bool> CompilePredicate(string query);

        /// <summary>
        /// Translates a query expression into a SQL WHERE clause for ClickHouse or DuckDB.
        /// </summary>
        /// <param name="query">The query string.</param>
        /// <returns>SQL WHERE clause string.</returns>
        string TranslateToSqlWhere(string query);

        /// <summary>
        /// Executes a query against an in-memory collection of log entries.
        /// </summary>
        /// <param name="entries">Source entries to search.</param>
        /// <param name="request">Query parameters.</param>
        /// <returns>Search query outcome.</returns>
        EventQueryResult ExecuteQuery(IEnumerable<TumLogEntry> entries, EventQueryRequest request);
    }
}
