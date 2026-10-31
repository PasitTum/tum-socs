// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Linq.Expressions;
using System.Reflection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Tum.Trust.Security.Core.Interfaces.Logging;
using Tum.Trust.Security.Core.Models.Logging;
using Tum.Trust.Security.Core.Models.Sigma;

namespace Tum.Trust.Security.Infrastructure.Sigma
{
    /// <summary>
    /// Native Sigma Rule Engine compiling open SigmaHQ rules into in-memory Expression Trees.
    /// Evaluates incoming log streams with zero reflection during runtime for ultra-low latency.
    /// </summary>
    public class SigmaRuleEngine : ISigmaRuleEngine
    {
        private class CompiledSigmaRule
        {
            public SigmaRule Rule { get; set; } = null!;
            public Func<TumLogEntry, bool> Evaluator { get; set; } = null!;
        }

        private readonly List<CompiledSigmaRule> _rules = new();
        private readonly object _lock = new();
        private readonly ILogger<SigmaRuleEngine> _logger;

        private static readonly MethodInfo StringContainsMethod = typeof(string).GetMethod(
            nameof(string.Contains),
            new[] { typeof(string), typeof(StringComparison) })!;

        private static readonly MethodInfo StringStartsWithMethod = typeof(string).GetMethod(
            nameof(string.StartsWith),
            new[] { typeof(string), typeof(StringComparison) })!;

        private static readonly MethodInfo StringEndsWithMethod = typeof(string).GetMethod(
            nameof(string.EndsWith),
            new[] { typeof(string), typeof(StringComparison) })!;

        private static readonly MethodInfo StringEqualsMethod = typeof(string).GetMethod(
            nameof(string.Equals),
            new[] { typeof(string), typeof(StringComparison) })!;

        /// <inheritdoc />
        public int ActiveRuleCount
        {
            get
            {
                lock (_lock)
                {
                    return _rules.Count;
                }
            }
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="SigmaRuleEngine"/> class.
        /// </summary>
        /// <param name="logger">Optional logger instance.</param>
        public SigmaRuleEngine(ILogger<SigmaRuleEngine>? logger = null)
        {
            _logger = logger ?? NullLogger<SigmaRuleEngine>.Instance;
        }

        /// <inheritdoc />
        public void RegisterRule(SigmaRule rule)
        {
            if (rule == null) throw new ArgumentNullException(nameof(rule));

            try
            {
                var evaluator = CompileRuleExpression(rule);
                lock (_lock)
                {
                    _rules.RemoveAll(r => r.Rule.Id == rule.Id);
                    _rules.Add(new CompiledSigmaRule { Rule = rule, Evaluator = evaluator });
                }
                _logger.LogInformation("Compiled and registered Sigma rule '{Title}' ({Id})", rule.Title, rule.Id);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to compile Sigma rule '{Title}' ({Id}): {Message}", rule.Title, rule.Id, ex.Message);
                throw;
            }
        }

        /// <inheritdoc />
        public void RegisterRules(IEnumerable<SigmaRule> rules)
        {
            if (rules == null) throw new ArgumentNullException(nameof(rules));
            foreach (var rule in rules)
            {
                RegisterRule(rule);
            }
        }

        /// <inheritdoc />
        public IReadOnlyList<SigmaMatchResult> Evaluate(TumLogEntry entry)
        {
            if (entry == null) return Array.Empty<SigmaMatchResult>();

            List<CompiledSigmaRule> snapshot;
            lock (_lock)
            {
                snapshot = new List<CompiledSigmaRule>(_rules);
            }

            var matches = new List<SigmaMatchResult>();
            for (int i = 0; i < snapshot.Count; i++)
            {
                var item = snapshot[i];
                try
                {
                    if (item.Evaluator(entry))
                    {
                        matches.Add(new SigmaMatchResult
                        {
                            RuleId = item.Rule.Id,
                            RuleTitle = item.Rule.Title,
                            Level = item.Rule.Level,
                            MitreTechniques = item.Rule.GetMitreTechniques(),
                            LogId = entry.LogId,
                            MatchedAtUtc = DateTimeOffset.UtcNow
                        });
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Error evaluating Sigma rule '{Title}': {Message}", item.Rule.Title, ex.Message);
                }
            }

            return matches;
        }

        /// <inheritdoc />
        public void ClearRules()
        {
            lock (_lock)
            {
                _rules.Clear();
            }
        }

        private Func<TumLogEntry, bool> CompileRuleExpression(SigmaRule rule)
        {
            var entryParam = Expression.Parameter(typeof(TumLogEntry), "entry");
            var selectorExpressions = new Dictionary<string, Expression>(StringComparer.OrdinalIgnoreCase);

            foreach (var kvp in rule.Selections)
            {
                string selectorName = kvp.Key;
                var fieldDict = kvp.Value;
                var fieldExpressions = new List<Expression>();

                foreach (var fieldKvp in fieldDict)
                {
                    string fieldWithModifier = fieldKvp.Key;
                    var values = fieldKvp.Value;
                    if (values == null || values.Count == 0) continue;

                    string fieldName = fieldWithModifier;
                    string modifier = "exact";

                    int pipeIdx = fieldWithModifier.IndexOf('|');
                    if (pipeIdx > 0)
                    {
                        fieldName = fieldWithModifier.Substring(0, pipeIdx).Trim();
                        modifier = fieldWithModifier.Substring(pipeIdx + 1).Trim().ToLowerInvariant();
                    }

                    var propExpr = ResolvePropertyExpression(entryParam, fieldName);
                    if (propExpr == null) continue;

                    // Build OR expressions across values
                    var valueDisjunctions = new List<Expression>();
                    foreach (var val in values)
                    {
                        var valueExpr = BuildFieldComparison(propExpr, val, modifier);
                        if (valueExpr != null)
                        {
                            valueDisjunctions.Add(valueExpr);
                        }
                    }

                    if (valueDisjunctions.Count > 0)
                    {
                        Expression combinedValues = valueDisjunctions[0];
                        for (int v = 1; v < valueDisjunctions.Count; v++)
                        {
                            combinedValues = Expression.OrElse(combinedValues, valueDisjunctions[v]);
                        }
                        fieldExpressions.Add(combinedValues);
                    }
                }

                if (fieldExpressions.Count > 0)
                {
                    Expression combinedFields = fieldExpressions[0];
                    for (int f = 1; f < fieldExpressions.Count; f++)
                    {
                        combinedFields = Expression.AndAlso(combinedFields, fieldExpressions[f]);
                    }
                    selectorExpressions[selectorName] = combinedFields;
                }
                else
                {
                    selectorExpressions[selectorName] = Expression.Constant(true);
                }
            }

            // Build condition expression tree
            Expression conditionExpr = BuildConditionExpression(rule.Condition, selectorExpressions);
            var lambda = Expression.Lambda<Func<TumLogEntry, bool>>(conditionExpr, entryParam);
            return lambda.Compile();
        }

        private static Expression BuildConditionExpression(string condition, Dictionary<string, Expression> selectors)
        {
            if (string.IsNullOrWhiteSpace(condition))
            {
                condition = "selection";
            }

            string normalized = condition.Trim();

            // Simple common pattern: "selection and not filter"
            if (normalized.Contains(" and not ", StringComparison.OrdinalIgnoreCase))
            {
                var parts = RegexSplit(normalized, @"\s+and\s+not\s+");
                if (parts.Length == 2 && selectors.TryGetValue(parts[0].Trim(), out var selExpr) && selectors.TryGetValue(parts[1].Trim(), out var filterExpr))
                {
                    return Expression.AndAlso(selExpr, Expression.Not(filterExpr));
                }
            }

            // Pattern: "selection1 and selection2"
            if (normalized.Contains(" and ", StringComparison.OrdinalIgnoreCase))
            {
                var parts = RegexSplit(normalized, @"\s+and\s+");
                Expression? agg = null;
                foreach (var p in parts)
                {
                    if (selectors.TryGetValue(p.Trim(), out var partExpr))
                    {
                        agg = agg == null ? partExpr : Expression.AndAlso(agg, partExpr);
                    }
                }
                if (agg != null) return agg;
            }

            // Pattern: "selection1 or selection2"
            if (normalized.Contains(" or ", StringComparison.OrdinalIgnoreCase))
            {
                var parts = RegexSplit(normalized, @"\s+or\s+");
                Expression? agg = null;
                foreach (var p in parts)
                {
                    if (selectors.TryGetValue(p.Trim(), out var partExpr))
                    {
                        agg = agg == null ? partExpr : Expression.OrElse(agg, partExpr);
                    }
                }
                if (agg != null) return agg;
            }

            // Single selector pattern: "selection"
            if (selectors.TryGetValue(normalized, out var singleExpr))
            {
                return singleExpr;
            }

            // Fallback: If only 1 selector exists, use it
            if (selectors.Count > 0)
            {
                return selectors.Values.First();
            }

            return Expression.Constant(false);
        }

        private static string[] RegexSplit(string input, string pattern)
        {
            return System.Text.RegularExpressions.Regex.Split(input, pattern, System.Text.RegularExpressions.RegexOptions.IgnoreCase);
        }

        private static Expression? ResolvePropertyExpression(ParameterExpression entryParam, string fieldName)
        {
            string? mappedName = fieldName.ToLowerInvariant() switch
            {
                "eventname" or "event_name" => nameof(TumLogEntry.EventName),
                "payload" or "payloadsanitized" or "commandline" or "message" => nameof(TumLogEntry.PayloadSanitized),
                "clientip" or "client_ip" or "ip" or "src_ip" => nameof(TumLogEntry.ClientIp),
                "requestpath" or "request_path" or "path" or "uri" or "url" => nameof(TumLogEntry.RequestPath),
                "httpmethod" or "http_method" or "method" => nameof(TumLogEntry.HttpMethod),
                "statuscode" or "status_code" or "status" => nameof(TumLogEntry.StatusCode),
                "userid" or "user_id" or "user" or "username" => nameof(TumLogEntry.UserId),
                "severity" => nameof(TumLogEntry.Severity),
                "standardaction" or "action" => nameof(TumLogEntry.StandardAction),
                "applicationname" or "app" => nameof(TumLogEntry.ApplicationName),
                "environment" or "env" => nameof(TumLogEntry.Environment),
                _ => null
            };

            if (mappedName == null) return null;

            var prop = typeof(TumLogEntry).GetProperty(mappedName);
            if (prop == null) return null;

            return Expression.Property(entryParam, prop);
        }

        private static Expression? BuildFieldComparison(Expression propExpr, string value, string modifier)
        {
            var comparisonConst = Expression.Constant(StringComparison.OrdinalIgnoreCase);

            // Handle string properties
            if (propExpr.Type == typeof(string))
            {
                var valConst = Expression.Constant(value, typeof(string));
                var notNullCheck = Expression.NotEqual(propExpr, Expression.Constant(null, typeof(string)));

                Expression matchExpr = modifier switch
                {
                    "contains" => Expression.Call(propExpr, StringContainsMethod, valConst, comparisonConst),
                    "startswith" => Expression.Call(propExpr, StringStartsWithMethod, valConst, comparisonConst),
                    "endswith" => Expression.Call(propExpr, StringEndsWithMethod, valConst, comparisonConst),
                    _ => Expression.Call(propExpr, StringEqualsMethod, valConst, comparisonConst)
                };

                return Expression.AndAlso(notNullCheck, matchExpr);
            }

            // Handle nullable int properties (e.g. StatusCode)
            if (propExpr.Type == typeof(int?))
            {
                if (int.TryParse(value, out int intVal))
                {
                    var valConst = Expression.Constant((int?)intVal, typeof(int?));
                    return Expression.Equal(propExpr, valConst);
                }
            }

            return null;
        }
    }
}
