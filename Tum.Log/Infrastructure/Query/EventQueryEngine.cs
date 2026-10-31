// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Tum.Trust.Security.Core.Interfaces.Logging;
using Tum.Trust.Security.Core.Models.Logging;
using Tum.Trust.Security.Core.Models.Query;

namespace Tum.Trust.Security.Infrastructure.Query
{
    /// <summary>
    /// Search Query Engine supporting Lucene-like field filters, full-text pattern matching,
    /// and SQL WHERE compilation for ClickHouse and DuckDB.
    /// </summary>
    public class EventQueryEngine : IEventQueryEngine
    {
        private readonly ILogger<EventQueryEngine> _logger;

        /// <summary>
        /// Initializes a new instance of the <see cref="EventQueryEngine"/> class.
        /// </summary>
        /// <param name="logger">Optional logger instance.</param>
        public EventQueryEngine(ILogger<EventQueryEngine>? logger = null)
        {
            _logger = logger ?? NullLogger<EventQueryEngine>.Instance;
        }

        /// <inheritdoc />
        public Func<TumLogEntry, bool> CompilePredicate(string query)
        {
            if (string.IsNullOrWhiteSpace(query) || query.Trim() == "*")
            {
                return _ => true;
            }

            var tokens = Tokenize(query.Trim());
            return BuildFilterDelegate(tokens);
        }

        /// <inheritdoc />
        public string TranslateToSqlWhere(string query)
        {
            if (string.IsNullOrWhiteSpace(query) || query.Trim() == "*")
            {
                return "1=1";
            }

            var sb = new StringBuilder();
            var tokens = Tokenize(query.Trim());

            for (int i = 0; i < tokens.Count; i++)
            {
                var token = tokens[i];
                if (token.Equals("AND", StringComparison.OrdinalIgnoreCase))
                {
                    sb.Append(" AND ");
                }
                else if (token.Equals("OR", StringComparison.OrdinalIgnoreCase))
                {
                    sb.Append(" OR ");
                }
                else if (token.Equals("NOT", StringComparison.OrdinalIgnoreCase))
                {
                    sb.Append(" NOT ");
                }
                else
                {
                    sb.Append(TokenToSqlCondition(token));
                }
            }

            return sb.Length > 0 ? sb.ToString() : "1=1";
        }

        /// <inheritdoc />
        public EventQueryResult ExecuteQuery(IEnumerable<TumLogEntry> entries, EventQueryRequest request)
        {
            if (entries == null) throw new ArgumentNullException(nameof(entries));
            if (request == null) throw new ArgumentNullException(nameof(request));

            var sw = Stopwatch.StartNew();
            var predicate = CompilePredicate(request.Query);
            string sqlWhere = TranslateToSqlWhere(request.Query);

            long scanned = 0;
            var matched = new List<TumLogEntry>();

            foreach (var entry in entries)
            {
                scanned++;

                // Apply time boundaries
                if (request.FromUtc.HasValue && entry.TimestampUtc < request.FromUtc.Value) continue;
                if (request.ToUtc.HasValue && entry.TimestampUtc > request.ToUtc.Value) continue;

                // Apply category boundary
                if (request.Category.HasValue && entry.Category != request.Category.Value) continue;

                // Apply compiled query predicate
                if (predicate(entry))
                {
                    matched.Add(entry);
                }
            }

            // Paginate
            int skip = Math.Max(0, request.Offset);
            int take = Math.Clamp(request.Limit, 1, 10_000);
            var page = matched.Skip(skip).Take(take).ToList();

            sw.Stop();

            return new EventQueryResult
            {
                QueryExecuted = request.Query,
                TotalScanned = scanned,
                TotalMatched = matched.Count,
                ExecutionDurationMs = sw.Elapsed.TotalMilliseconds,
                Items = page,
                TranslatedSqlWhere = sqlWhere
            };
        }

        private static List<string> Tokenize(string query)
        {
            var tokens = new List<string>();
            var regex = new Regex(@"(?:[^\s""']+|""[^""]*""|'[^']*')+", RegexOptions.Compiled);
            var matches = regex.Matches(query);

            foreach (Match m in matches)
            {
                string val = m.Value.Trim();
                if (!string.IsNullOrEmpty(val))
                {
                    tokens.Add(val);
                }
            }

            return tokens;
        }

        private static Func<TumLogEntry, bool> BuildFilterDelegate(List<string> tokens)
        {
            var termPredicates = new List<(Func<TumLogEntry, bool> Predicate, string Op)>();
            string currentOp = "AND";

            for (int i = 0; i < tokens.Count; i++)
            {
                string token = tokens[i];

                if (token.Equals("AND", StringComparison.OrdinalIgnoreCase))
                {
                    currentOp = "AND";
                }
                else if (token.Equals("OR", StringComparison.OrdinalIgnoreCase))
                {
                    currentOp = "OR";
                }
                else if (token.Equals("NOT", StringComparison.OrdinalIgnoreCase))
                {
                    currentOp = "NOT";
                }
                else
                {
                    var singlePred = ParseSingleCondition(token);
                    termPredicates.Add((singlePred, currentOp));
                    currentOp = "AND"; // reset to default
                }
            }

            return entry =>
            {
                if (termPredicates.Count == 0) return true;

                bool result = true;
                for (int i = 0; i < termPredicates.Count; i++)
                {
                    var (pred, op) = termPredicates[i];
                    bool matches = pred(entry);

                    if (i == 0)
                    {
                        result = op == "NOT" ? !matches : matches;
                    }
                    else
                    {
                        if (op == "OR")
                        {
                            result = result || matches;
                        }
                        else if (op == "NOT")
                        {
                            result = result && !matches;
                        }
                        else
                        {
                            result = result && matches;
                        }
                    }
                }

                return result;
            };
        }

        private static Func<TumLogEntry, bool> ParseSingleCondition(string token)
        {
            int colonIdx = token.IndexOf(':');

            // Free text matching across multiple fields
            if (colonIdx <= 0)
            {
                string term = token.Trim('"', '\'');
                return entry =>
                    (entry.PayloadSanitized?.Contains(term, StringComparison.OrdinalIgnoreCase) ?? false) ||
                    (entry.EventName?.Contains(term, StringComparison.OrdinalIgnoreCase) ?? false) ||
                    (entry.RequestPath?.Contains(term, StringComparison.OrdinalIgnoreCase) ?? false) ||
                    (entry.ClientIp?.Contains(term, StringComparison.OrdinalIgnoreCase) ?? false);
            }

            string field = token.Substring(0, colonIdx).Trim().ToLowerInvariant();
            string val = token.Substring(colonIdx + 1).Trim().Trim('"', '\'');

            return field switch
            {
                "category" => entry => entry.Category.ToString().Equals(val, StringComparison.OrdinalIgnoreCase),
                "severity" => entry => entry.Severity.Equals(val, StringComparison.OrdinalIgnoreCase),
                "event" or "eventname" => entry => MatchWildcard(entry.EventName, val),
                "ip" or "clientip" => entry => MatchWildcard(entry.ClientIp, val),
                "user" or "userid" => entry => MatchWildcard(entry.UserId ?? string.Empty, val),
                "path" or "requestpath" => entry => MatchWildcard(entry.RequestPath ?? string.Empty, val),
                "method" or "httpmethod" => entry => (entry.HttpMethod ?? string.Empty).Equals(val, StringComparison.OrdinalIgnoreCase),
                "action" or "standardaction" => entry => MatchWildcard(entry.StandardAction, val),
                "app" or "application" => entry => (entry.ApplicationName ?? string.Empty).Equals(val, StringComparison.OrdinalIgnoreCase),
                "env" or "environment" => entry => (entry.Environment ?? string.Empty).Equals(val, StringComparison.OrdinalIgnoreCase),
                "status" or "statuscode" => entry => int.TryParse(val, out int code) && entry.StatusCode == code,
                _ => entry => entry.PayloadSanitized?.Contains(val, StringComparison.OrdinalIgnoreCase) ?? false
            };
        }

        private static bool MatchWildcard(string input, string pattern)
        {
            if (string.IsNullOrEmpty(input) && string.IsNullOrEmpty(pattern)) return true;
            if (string.IsNullOrEmpty(input)) return false;

            if (pattern.EndsWith("*") && pattern.StartsWith("*"))
            {
                string core = pattern.Trim('*');
                return input.Contains(core, StringComparison.OrdinalIgnoreCase);
            }
            if (pattern.EndsWith("*"))
            {
                string prefix = pattern.TrimEnd('*');
                return input.StartsWith(prefix, StringComparison.OrdinalIgnoreCase);
            }
            if (pattern.StartsWith("*"))
            {
                string suffix = pattern.TrimStart('*');
                return input.EndsWith(suffix, StringComparison.OrdinalIgnoreCase);
            }

            return input.Equals(pattern, StringComparison.OrdinalIgnoreCase);
        }

        private static string TokenToSqlCondition(string token)
        {
            int colonIdx = token.IndexOf(':');
            if (colonIdx <= 0)
            {
                string term = token.Trim('"', '\'').Replace("'", "''");
                return $"(payload_sanitized LIKE '%{term}%' OR event_name LIKE '%{term}%' OR client_ip LIKE '%{term}%')";
            }

            string field = token.Substring(0, colonIdx).Trim().ToLowerInvariant();
            string val = token.Substring(colonIdx + 1).Trim().Trim('"', '\'').Replace("'", "''");

            string sqlCol = field switch
            {
                "category" => "category",
                "severity" => "severity",
                "event" or "eventname" => "event_name",
                "ip" or "clientip" => "client_ip",
                "user" or "userid" => "user_id",
                "path" or "requestpath" => "request_path",
                "method" or "httpmethod" => "http_method",
                "status" or "statuscode" => "status_code",
                "action" or "standardaction" => "standard_action",
                "app" or "application" => "application_name",
                "env" or "environment" => "environment",
                _ => "payload_sanitized"
            };

            if (val.Contains('*'))
            {
                string likeVal = val.Replace('*', '%');
                return $"{sqlCol} LIKE '{likeVal}'";
            }

            if (sqlCol == "status_code" && int.TryParse(val, out int code))
            {
                return $"{sqlCol} = {code}";
            }

            return $"{sqlCol} = '{val}'";
        }
    }
}
