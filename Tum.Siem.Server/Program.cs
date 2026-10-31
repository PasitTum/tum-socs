// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.IO;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Tum.Log;
using Tum.Trust.Security.Core.Interfaces.Logging;
using Tum.Trust.Security.Core.Models.Alerts;
using Tum.Trust.Security.Core.Models.Logging;
using Tum.Trust.Security.Core.Models.Query;
using Tum.Trust.Security.Core.Models.Risk;
using Tum.Trust.Security.Infrastructure.Analytics;
using Tum.Trust.Security.Infrastructure.Query;
using Tum.Trust.Security.Infrastructure.Serialization;
using Tum.Trust.Security.Infrastructure.Sigma;

var builder = WebApplication.CreateBuilder(args);

// Configure OpenSIEM Services
builder.Services.AddTumLog(options =>
{
    options.ApplicationName = "TUM-OpenSIEM-Core";
    options.Environment = "Production";
    options.EnableAutoPiiMasking = true;
    options.EnableThreatDetection = true;
    options.EnableMerkleChaining = true;
    options.WormRetentionDays = 90;
    options.StorageDirectory = Path.Combine(AppContext.BaseDirectory, "tum_logs");
});

builder.Services.AddSingleton<IEventQueryEngine, EventQueryEngine>();
builder.Services.AddSingleton<IThreatAnalyticsEngine, ThreatAnalyticsEngine>();
builder.Services.AddCors(opts => opts.AddDefaultPolicy(p => p.AllowAnyOrigin().AllowAnyHeader().AllowAnyMethod()));

var app = builder.Build();
app.UseCors();

// Auto-load Sigma rules from rules directory
var sigmaEngine = app.Services.GetRequiredService<ISigmaRuleEngine>();
LoadCommunityRules(sigmaEngine);

// -------------------------------------------------------------
// REST API ENDPOINTS
// -------------------------------------------------------------

// 1. Unified Web Console (Home)
app.MapGet("/", async (HttpContext ctx) =>
{
    string htmlPath = FindVisualizerHtmlPath();
    if (File.Exists(htmlPath))
    {
        ctx.Response.ContentType = "text/html; charset=utf-8";
        await ctx.Response.SendFileAsync(htmlPath);
    }
    else
    {
        await ctx.Response.WriteAsync("<h1>TUM-OpenSIEM Core Online</h1><p>Visualizer HTML template not found.</p>");
    }
});

// 2. Health & Engine Status
app.MapGet("/api/status", async (ITamperProofLogStorage storage, ISigmaRuleEngine sigma, TumLogOptions opts) =>
{
    bool intact = await storage.VerifyChainIntegrityAsync();
    var recent = await storage.GetRecentEntriesAsync(1);
    string lastHash = recent.Count > 0 ? recent[0].TamperProofHash : "GENESIS_LEGAL_SEAL";
    string merkleRoot = recent.Count > 0 ? recent[0].MerkleRoot : "GENESIS_MERKLE_ROOT";

    return Results.Ok(new
    {
        Engine = "TUM-OpenSIEM Sovereign Edition",
        Version = "2.0.0-PROD",
        Status = "Operational",
        ChainIntact = intact,
        LastTamperProofHash = lastHash,
        GlobalMerkleRoot = merkleRoot,
        ActiveSigmaRules = sigma.ActiveRuleCount,
        NtpSynchronizedWith = opts.NtpServerHost,
        WormRetentionDays = opts.WormRetentionDays,
        TimestampUtc = DateTimeOffset.UtcNow
    });
});

// 3. Live Dashboard Summary
app.MapGet("/api/dashboard/summary", (IThreatAnalyticsEngine analytics) =>
{
    return Results.Ok(analytics.GetDashboardSummary());
});

// 4. Live Correlated Attack Graph
app.MapGet("/api/dashboard/attack-graph", (IThreatAnalyticsEngine analytics, int? limit) =>
{
    return Results.Ok(analytics.GetAttackGraph(limit ?? 50));
});

// 5. Legal Compliance Audit Report (Section 26 & ISO 27001)
app.MapGet("/api/dashboard/compliance", async (IThreatAnalyticsEngine analytics) =>
{
    var report = await analytics.GenerateComplianceAuditAsync();
    return Results.Ok(report);
});

// 6. High-Throughput Ingestion Endpoint
app.MapPost("/api/logs/ingest", async (
    TumLogEntry entry,
    ITumLogEngine engine,
    ISigmaRuleEngine sigma,
    IDynamicRiskEngine riskEngine,
    IThreatAnalyticsEngine analytics,
    IAlertDispatcher alertDispatcher) =>
{
    if (entry == null) return Results.BadRequest("Log entry cannot be null");

    // 1. Process log through TUMLog Core (PII masking, Inbound threat detection, WORM Merkle chaining)
    var processed = await engine.LogAsync(entry);

    // 2. Evaluate against compiled in-memory Sigma rules
    var sigmaMatches = sigma.Evaluate(processed);

    // 3. Calculate continuous dynamic risk score (0-100)
    var risk = riskEngine.EvaluateRisk(processed, sigmaMatches);

    // 4. Record into threat analytics and attack graph
    analytics.RecordEvent(processed, sigmaMatches);

    // 5. If risk exceeds alert threshold, dispatch real-time alerts
    if (risk.ShouldAlert(70.0))
    {
        var alert = new AlertNotification
        {
            Title = sigmaMatches.Count > 0 ? sigmaMatches[0].RuleTitle : $"Threat Detected: {processed.EventName}",
            Description = $"High risk event with score {risk.Score}/100 detected from {processed.ClientIp}",
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

        _ = Task.Run(() => alertDispatcher.DispatchAlertAsync(alert));
    }

    return Results.Ok(new
    {
        LogId = processed.LogId,
        TamperProofHash = processed.TamperProofHash,
        MerkleRoot = processed.MerkleRoot,
        PiiRedacted = processed.PiiRedactedCount,
        RiskScore = risk.Score,
        SeverityBand = risk.SeverityBand.ToString(),
        SigmaMatchesCount = sigmaMatches.Count,
        TimestampUtc = processed.TimestampUtc
    });
});

// 7. Lucene / SQL-like Event Query Explorer
app.MapGet("/api/logs/query", async (string? q, int? limit, int? offset, ITamperProofLogStorage storage, IEventQueryEngine queryEngine) =>
{
    var entries = await storage.GetRecentEntriesAsync(500);
    var request = new EventQueryRequest
    {
        Query = q ?? "*",
        Limit = limit ?? 100,
        Offset = offset ?? 0
    };

    var result = queryEngine.ExecuteQuery(entries, request);
    return Results.Ok(result);
});

// 8. List Sigma Rules
app.MapGet("/api/sigma/rules", (ISigmaRuleEngine sigma) =>
{
    return Results.Ok(new { ActiveRuleCount = sigma.ActiveRuleCount });
});

// 9. Register Community Sigma Rule
app.MapPost("/api/sigma/rules", async (HttpRequest req, ISigmaRuleEngine sigma) =>
{
    using var reader = new StreamReader(req.Body);
    string yaml = await reader.ReadToEndAsync();
    if (string.IsNullOrWhiteSpace(yaml)) return Results.BadRequest("YAML body is required");

    try
    {
        var rule = SigmaRuleParser.ParseYaml(yaml);
        sigma.RegisterRule(rule);
        return Results.Ok(new { Message = "Rule registered and compiled successfully", RuleId = rule.Id, Title = rule.Title });
    }
    catch (Exception ex)
    {
        return Results.BadRequest(new { Error = ex.Message });
    }
});

// 10. Live Event Feed
app.MapGet("/api/events/live", async (ITamperProofLogStorage storage) =>
{
    var entries = await storage.GetRecentEntriesAsync(30);
    return Results.Ok(entries);
});

app.Run();

// Helper method to load community rules
static void LoadCommunityRules(ISigmaRuleEngine sigmaEngine)
{
    try
    {
        string current = AppContext.BaseDirectory;
        string? rulesDir = null;

        for (int i = 0; i < 5; i++)
        {
            string candidate = Path.Combine(current, "rules");
            if (Directory.Exists(candidate))
            {
                rulesDir = candidate;
                break;
            }
            var parent = Directory.GetParent(current);
            if (parent == null) break;
            current = parent.FullName;
        }

        if (rulesDir != null && Directory.Exists(rulesDir))
        {
            var yamlFiles = Directory.GetFiles(rulesDir, "*.yml", SearchOption.AllDirectories);
            foreach (var file in yamlFiles)
            {
                try
                {
                    string content = File.ReadAllText(file);
                    var rule = SigmaRuleParser.ParseYaml(content);
                    sigmaEngine.RegisterRule(rule);
                }
                catch { }
            }
        }
    }
    catch { }
}

static string FindVisualizerHtmlPath()
{
    string current = AppContext.BaseDirectory;
    for (int i = 0; i < 5; i++)
    {
        string candidate = Path.Combine(current, "visualizers", "index.html");
        if (File.Exists(candidate)) return candidate;
        var parent = Directory.GetParent(current);
        if (parent == null) break;
        current = parent.FullName;
    }
    return Path.Combine(AppContext.BaseDirectory, "visualizers", "index.html");
}

public partial class Program { }
