// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using System.Collections.Generic;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Tum.Trust.Security.Core.Interfaces.Logging;
using Tum.Trust.Security.Core.Models.Logging;
using Tum.Trust.Security.Core.Models.Risk;
using Tum.Trust.Security.Core.Models.Sigma;

namespace Tum.Trust.Security.Infrastructure.Risk
{
    /// <summary>
    /// Evaluates continuous dynamic threat risk scores (0-100) based on Sigma matches,
    /// MITRE ATT&amp;CK taxonomy, PII exposure, and real-time defense interceptions.
    /// </summary>
    public class DynamicRiskEngine : IDynamicRiskEngine
    {
        private readonly DynamicRiskOptions _options;
        private readonly ILogger<DynamicRiskEngine> _logger;

        /// <summary>
        /// Initializes a new instance of the <see cref="DynamicRiskEngine"/> class.
        /// </summary>
        /// <param name="options">Risk options.</param>
        /// <param name="logger">Optional logger instance.</param>
        public DynamicRiskEngine(
            DynamicRiskOptions? options = null,
            ILogger<DynamicRiskEngine>? logger = null)
        {
            _options = options ?? new DynamicRiskOptions();
            _logger = logger ?? NullLogger<DynamicRiskEngine>.Instance;
        }

        /// <inheritdoc />
        public RiskScoreResult EvaluateRisk(TumLogEntry entry, IReadOnlyList<SigmaMatchResult>? sigmaMatches = null)
        {
            if (entry == null) throw new ArgumentNullException(nameof(entry));

            var factors = new List<RiskFactor>();
            double rawScore = 0.0;

            // 1. Evaluate Sigma Rule Matches
            if (sigmaMatches != null && sigmaMatches.Count > 0)
            {
                foreach (var match in sigmaMatches)
                {
                    double points = match.Level switch
                    {
                        SigmaRuleLevel.Critical => _options.SigmaCriticalScore,
                        SigmaRuleLevel.High => _options.SigmaHighScore,
                        SigmaRuleLevel.Medium => _options.SigmaMediumScore,
                        _ => _options.SigmaLowScore
                    };

                    rawScore += points;
                    factors.Add(new RiskFactor
                    {
                        FactorName = "SigmaRuleMatch",
                        Description = $"Triggered Sigma rule '{match.RuleTitle}' ({match.Level})",
                        ContributedScore = points
                    });

                    // Bonus for High-Impact MITRE ATT&CK techniques
                    if (match.MitreTechniques.Count > 0)
                    {
                        bool hasHighImpact = match.MitreTechniques.Exists(t =>
                            t.StartsWith("T1059", StringComparison.OrdinalIgnoreCase) || // Execution
                            t.StartsWith("T1068", StringComparison.OrdinalIgnoreCase) || // Privilege Escalation
                            t.StartsWith("T1003", StringComparison.OrdinalIgnoreCase) || // Credential Access
                            t.StartsWith("T1041", StringComparison.OrdinalIgnoreCase));  // Exfiltration

                        if (hasHighImpact)
                        {
                            rawScore += _options.HighImpactMitreBonus;
                            factors.Add(new RiskFactor
                            {
                                FactorName = "HighImpactMitreTechnique",
                                Description = $"High-impact MITRE ATT&CK technique detected: {string.Join(", ", match.MitreTechniques)}",
                                ContributedScore = _options.HighImpactMitreBonus
                            });
                        }
                    }
                }
            }

            // 2. Evaluate Inbound Web Application Threat Detections (SQLi, XSS, Path Traversal)
            if (entry.SecurityThreats != null && entry.SecurityThreats.Count > 0)
            {
                double points = _options.InboundThreatScore;
                rawScore += points;
                factors.Add(new RiskFactor
                {
                    FactorName = "InboundThreatDetected",
                    Description = $"{entry.SecurityThreats.Count} inbound application attack vector(s) identified",
                    ContributedScore = points
                });
            }

            // 3. Evaluate Outbound Sensitive Data Exfiltration Leaks
            if (entry.OutboundLeaks != null && entry.OutboundLeaks.Count > 0)
            {
                double points = _options.OutboundLeakScore;
                rawScore += points;
                factors.Add(new RiskFactor
                {
                    FactorName = "OutboundDataLeak",
                    Description = $"{entry.OutboundLeaks.Count} outbound secret or PII exfiltration leak(s) intercepted",
                    ContributedScore = points
                });
            }

            // 4. Evaluate PII Exposure Density
            if (entry.PiiRedactedCount > 0)
            {
                double piiPoints = Math.Min(entry.PiiRedactedCount * _options.PiiExposureUnitScore, _options.MaxPiiRiskScore);
                rawScore += piiPoints;
                factors.Add(new RiskFactor
                {
                    FactorName = "PiiExposureDensity",
                    Description = $"{entry.PiiRedactedCount} sensitive personal data element(s) redacted",
                    ContributedScore = piiPoints
                });
            }

            // 5. Apply Environment Multiplier (e.g. Production = 1.2x)
            double envMultiplier = 1.0;
            if (!string.IsNullOrEmpty(entry.Environment) &&
                _options.EnvironmentMultipliers.TryGetValue(entry.Environment, out double configuredMultiplier))
            {
                envMultiplier = configuredMultiplier;
            }

            double weightedScore = rawScore * envMultiplier;
            if (Math.Abs(envMultiplier - 1.0) > 0.001 && rawScore > 0)
            {
                factors.Add(new RiskFactor
                {
                    FactorName = "EnvironmentWeight",
                    Description = $"Applied {entry.Environment} asset multiplier (x{envMultiplier:F2})",
                    ContributedScore = weightedScore - rawScore,
                    Weight = envMultiplier
                });
            }

            // Clamp between 0.0 and 100.0
            double finalScore = Math.Clamp(Math.Round(weightedScore, 1), 0.0, 100.0);

            var severityBand = finalScore switch
            {
                >= 90.0 => RiskSeverityBand.Critical,
                >= 70.0 => RiskSeverityBand.High,
                >= 40.0 => RiskSeverityBand.Medium,
                >= 20.0 => RiskSeverityBand.Low,
                _ => RiskSeverityBand.Informational
            };

            return new RiskScoreResult
            {
                Score = finalScore,
                SeverityBand = severityBand,
                Factors = factors,
                EvaluatedAtUtc = DateTimeOffset.UtcNow
            };
        }
    }
}
