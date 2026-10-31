// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Collections.Generic;
using Tum.Trust.Security.Core.Models.Logging;
using Tum.Trust.Security.Core.Models.Risk;
using Tum.Trust.Security.Core.Models.Sigma;
using Tum.Trust.Security.Infrastructure.Risk;
using Xunit;

namespace Tum.Trust.Security.Tests
{
    public class DynamicRiskEngineTests
    {
        [Fact]
        public void EvaluateRisk_CalculatesCriticalScore_ForCompoundedThreats()
        {
            var engine = new DynamicRiskEngine();

            var entry = new TumLogEntry
            {
                Environment = "Production",
                PiiRedactedCount = 3,
                SecurityThreats = new List<SecurityThreatAlert>
                {
                    new SecurityThreatAlert { ThreatType = ThreatType.SqlInjection, Severity = "Critical" }
                },
                OutboundLeaks = new List<OutboundLeakDetection>
                {
                    new OutboundLeakDetection { LeakType = OutboundLeakType.SecretTokenExposed, Severity = "Critical" }
                }
            };

            var sigmaMatches = new List<SigmaMatchResult>
            {
                new SigmaMatchResult
                {
                    RuleId = "sigma-crit-01",
                    RuleTitle = "PowerShell CobaltStrike Beacon Execution",
                    Level = SigmaRuleLevel.Critical,
                    MitreTechniques = new List<string> { "T1059.001" } // High-impact Execution
                }
            };

            var result = engine.EvaluateRisk(entry, sigmaMatches);

            // Raw calculation:
            // Sigma Critical = 50
            // Mitre High-Impact Bonus = 15
            // Inbound Threat = 30
            // Outbound Leak = 35
            // PII Exposure = 3 * 5 = 15
            // Sum = 145 * Production Multiplier (1.2x) = 174 -> Clamped to 100.0
            Assert.Equal(100.0, result.Score);
            Assert.Equal(RiskSeverityBand.Critical, result.SeverityBand);
            Assert.True(result.ShouldAlert(70.0));
            Assert.NotEmpty(result.Factors);
        }

        [Fact]
        public void EvaluateRisk_ReturnsInformational_ForBenignActivity()
        {
            var engine = new DynamicRiskEngine();

            var entry = new TumLogEntry
            {
                EventName = "USER.NAVIGATE",
                Environment = "Development",
                PiiRedactedCount = 0
            };

            var result = engine.EvaluateRisk(entry);

            Assert.Equal(0.0, result.Score);
            Assert.Equal(RiskSeverityBand.Informational, result.SeverityBand);
            Assert.False(result.ShouldAlert(70.0));
        }

        [Fact]
        public void EvaluateRisk_AppliesMediumRisk_ForLowSigmaAndPii()
        {
            var engine = new DynamicRiskEngine();

            var entry = new TumLogEntry
            {
                Environment = "Staging", // 1.0 multiplier
                PiiRedactedCount = 4    // 4 * 5 = 20 pts
            };

            var sigmaMatches = new List<SigmaMatchResult>
            {
                new SigmaMatchResult
                {
                    RuleId = "sigma-med-01",
                    RuleTitle = "Multiple Failed Logins",
                    Level = SigmaRuleLevel.Medium // 20 pts
                }
            };

            var result = engine.EvaluateRisk(entry, sigmaMatches);

            // Total = 20 + 20 = 40 pts -> Medium Severity Band
            Assert.Equal(40.0, result.Score);
            Assert.Equal(RiskSeverityBand.Medium, result.SeverityBand);
            Assert.False(result.ShouldAlert(70.0));
        }
    }
}
