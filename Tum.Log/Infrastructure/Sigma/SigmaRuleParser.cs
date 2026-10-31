// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using System.Collections.Generic;
using System.IO;
using System.Text.RegularExpressions;
using Tum.Trust.Security.Core.Models.Sigma;

namespace Tum.Trust.Security.Infrastructure.Sigma
{
    /// <summary>
    /// Lightweight, zero-dependency, Native AOT-compatible parser for open SigmaHQ YAML rule definitions.
    /// </summary>
    public static class SigmaRuleParser
    {
        /// <summary>
        /// Parses a Sigma rule from a YAML string.
        /// </summary>
        /// <param name="yaml">YAML formatted Sigma rule.</param>
        /// <returns>Populated <see cref="SigmaRule"/> instance.</returns>
        public static SigmaRule ParseYaml(string yaml)
        {
            if (string.IsNullOrWhiteSpace(yaml))
            {
                throw new ArgumentException("Sigma rule YAML cannot be empty", nameof(yaml));
            }

            var rule = new SigmaRule();
            using var reader = new StringReader(yaml);
            string? line;
            string currentSection = string.Empty;
            string currentSelector = string.Empty;
            string currentField = string.Empty;

            while ((line = reader.ReadLine()) != null)
            {
                string trimmed = line.Trim();
                if (string.IsNullOrEmpty(trimmed) || trimmed.StartsWith("#"))
                {
                    continue;
                }

                int indent = line.Length - line.TrimStart().Length;

                // Root-level fields
                if (indent == 0)
                {
                    currentSection = string.Empty;
                    currentSelector = string.Empty;
                    currentField = string.Empty;

                    var colonIndex = line.IndexOf(':');
                    if (colonIndex > 0)
                    {
                        string key = line.Substring(0, colonIndex).Trim();
                        string val = line.Substring(colonIndex + 1).Trim().Trim('\'', '"');

                        switch (key.ToLowerInvariant())
                        {
                            case "title":
                                rule.Title = val;
                                break;
                            case "id":
                                rule.Id = val;
                                break;
                            case "description":
                                rule.Description = val;
                                break;
                            case "status":
                                rule.Status = val;
                                break;
                            case "level":
                                rule.Level = ParseLevel(val);
                                break;
                            case "tags":
                                currentSection = "tags";
                                break;
                            case "logsource":
                                currentSection = "logsource";
                                break;
                            case "detection":
                                currentSection = "detection";
                                break;
                            case "falsepositives":
                                currentSection = "falsepositives";
                                break;
                        }
                    }
                    continue;
                }

                // Sub-sections
                if (currentSection == "tags" && trimmed.StartsWith("-"))
                {
                    rule.Tags.Add(trimmed.Substring(1).Trim().Trim('\'', '"'));
                }
                else if (currentSection == "falsepositives" && trimmed.StartsWith("-"))
                {
                    rule.FalsePositives.Add(trimmed.Substring(1).Trim().Trim('\'', '"'));
                }
                else if (currentSection == "logsource")
                {
                    var parts = trimmed.Split(new[] { ':' }, 2);
                    if (parts.Length == 2)
                    {
                        string k = parts[0].Trim().ToLowerInvariant();
                        string v = parts[1].Trim().Trim('\'', '"');
                        if (k == "category") rule.LogSource.Category = v;
                        else if (k == "product") rule.LogSource.Product = v;
                        else if (k == "service") rule.LogSource.Service = v;
                    }
                }
                else if (currentSection == "detection")
                {
                    var colonIdx = trimmed.IndexOf(':');
                    if (indent <= 4 && colonIdx > 0 && !trimmed.StartsWith("-"))
                    {
                        string key = trimmed.Substring(0, colonIdx).Trim();
                        string val = trimmed.Substring(colonIdx + 1).Trim().Trim('\'', '"');

                        if (key.Equals("condition", StringComparison.OrdinalIgnoreCase))
                        {
                            rule.Condition = val;
                            currentSelector = string.Empty;
                            currentField = string.Empty;
                        }
                        else
                        {
                            currentSelector = key;
                            currentField = string.Empty;
                            if (!rule.Selections.ContainsKey(currentSelector))
                            {
                                rule.Selections[currentSelector] = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
                            }
                        }
                    }
                    else if (!string.IsNullOrEmpty(currentSelector))
                    {
                        if (trimmed.StartsWith("-"))
                        {
                            // List item under currentField
                            string listItem = trimmed.Substring(1).Trim().Trim('\'', '"');
                            if (!string.IsNullOrEmpty(currentField) && rule.Selections[currentSelector].TryGetValue(currentField, out var list))
                            {
                                list.Add(listItem);
                            }
                        }
                        else if (colonIdx > 0)
                        {
                            string field = trimmed.Substring(0, colonIdx).Trim();
                            string val = trimmed.Substring(colonIdx + 1).Trim().Trim('\'', '"');

                            currentField = field;
                            if (!rule.Selections[currentSelector].ContainsKey(field))
                            {
                                rule.Selections[currentSelector][field] = new List<string>();
                            }

                            if (!string.IsNullOrEmpty(val))
                            {
                                rule.Selections[currentSelector][field].Add(val);
                            }
                        }
                    }
                }
            }

            return rule;
        }

        private static SigmaRuleLevel ParseLevel(string level)
        {
            return level.ToLowerInvariant() switch
            {
                "low" => SigmaRuleLevel.Low,
                "high" => SigmaRuleLevel.High,
                "critical" => SigmaRuleLevel.Critical,
                _ => SigmaRuleLevel.Medium
            };
        }
    }
}
