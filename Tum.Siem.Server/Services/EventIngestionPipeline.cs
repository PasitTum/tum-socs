// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Tum.Siem.Server.Configuration;
using Tum.Siem.Server.DTOs.Responses;
using Tum.Trust.Security.Core.Interfaces.Logging;
using Tum.Trust.Security.Core.Models.Alerts;
using Tum.Trust.Security.Core.Models.Logging;

namespace Tum.Siem.Server.Services;

/// <summary>
/// Production event ingestion pipeline executing multi-stage threat detection and alerting.
/// </summary>
public sealed class EventIngestionPipeline : IEventIngestionPipeline
{
    private readonly ITumLogEngine _engine;
    private readonly ISigmaRuleEngine _sigma;
    private readonly IDynamicRiskEngine _riskEngine;
    private readonly IThreatAnalyticsEngine _analytics;
    private readonly IAlertDispatcher _alertDispatcher;
    private readonly SiemServerOptions _options;
    private readonly ILogger<EventIngestionPipeline> _logger;

    public EventIngestionPipeline(
        ITumLogEngine engine,
        ISigmaRuleEngine sigma,
        IDynamicRiskEngine riskEngine,
        IThreatAnalyticsEngine analytics,
        IAlertDispatcher alertDispatcher,
        IOptions<SiemServerOptions> options,
        ILogger<EventIngestionPipeline> logger)
    {
        _engine = engine ?? throw new ArgumentNullException(nameof(engine));
        _sigma = sigma ?? throw new ArgumentNullException(nameof(sigma));
        _riskEngine = riskEngine ?? throw new ArgumentNullException(nameof(riskEngine));
        _analytics = analytics ?? throw new ArgumentNullException(nameof(analytics));
        _alertDispatcher = alertDispatcher ?? throw new ArgumentNullException(nameof(alertDispatcher));
        _options = options?.Value ?? new SiemServerOptions();
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    public async Task<IngestLogResponse> IngestAsync(TumLogEntry entry, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(entry);

        // 1. Process log through TUMLog Core (PII masking, Inbound threat detection, WORM Merkle chaining)
        var processed = await _engine.LogAsync(entry);

        // 2. Evaluate against compiled in-memory Sigma rules
        var sigmaMatches = _sigma.Evaluate(processed);

        // 3. Calculate continuous dynamic risk score (0-100)
        var risk = _riskEngine.EvaluateRisk(processed, sigmaMatches);

        // 4. Record into threat analytics and attack graph
        _analytics.RecordEvent(processed, sigmaMatches);

        // 5. If risk exceeds alert threshold, dispatch real-time alerts asynchronously
        if (risk.ShouldAlert(_options.AlertRiskThreshold))
        {
            var alert = new AlertNotification
            {
                Title = sigmaMatches.Count > 0 ? sigmaMatches[0].RuleTitle : $"Threat Detected: {processed.EventName}",
                Description = $"High risk event with score {risk.Score:F1}/100 detected from {processed.ClientIp}",
                RiskScore = risk.Score,
                SeverityBand = risk.SeverityBand,
                ClientIp = processed.ClientIp,
                Environment = processed.Environment,
                StandardAction = processed.StandardAction,
                MitreTechniques = sigmaMatches.SelectMany(m => m.MitreTechniques).Distinct().ToList(),
                MatchedRules = sigmaMatches.ToList(),
                RiskFactors = risk.Factors,
                LogEntry = processed
            };

            _ = Task.Run(async () =>
            {
                try
                {
                    await _alertDispatcher.DispatchAlertAsync(alert);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Failed to dispatch alert for EventId: {EventId}", processed.LogId);
                }
            }, CancellationToken.None);
        }

        return new IngestLogResponse
        {
            LogId = processed.LogId,
            TamperProofHash = processed.TamperProofHash,
            MerkleRoot = processed.MerkleRoot,
            PiiRedacted = processed.PiiRedactedCount,
            RiskScore = risk.Score,
            SeverityBand = risk.SeverityBand.ToString(),
            SigmaMatchesCount = sigmaMatches.Count,
            TimestampUtc = processed.TimestampUtc
        };
    }
}
