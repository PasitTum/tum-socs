// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using Tum.Siem.Server.Services;
using Tum.Trust.Security.Core.Models.Logging;
using Xunit;

namespace Tum.Trust.Security.Tests;

public class SmartSamplingGovernorTests
{
    [Fact]
    public void Governor_UnderNormalConditions_Should_Retain_All_Logs()
    {
        var governor = new SmartSamplingGovernor();
        governor.Configure(forceSurge: false, surgeThresholdEps: 50_000, benignSampleRate: 20);

        var benignLog = new TumLogEntry
        {
            EventName = "HTTP.GET.STATIC",
            Category = LogCategory.SystemDiagnostic,
            Severity = "Information",
            HttpMethod = "GET",
            StatusCode = 200,
            RequestPath = "/assets/app.js"
        };

        var decision = governor.Evaluate(benignLog);

        Assert.False(decision.ShouldSampleOut);
        Assert.Equal(1, decision.SampleWeight);
    }

    [Fact]
    public void Governor_InSurgeMode_Should_Sample_Benign_Noise_At_Sample_Rate()
    {
        var governor = new SmartSamplingGovernor();
        governor.Configure(forceSurge: true, surgeThresholdEps: 1000, benignSampleRate: 5);

        int retained = 0;
        int sampledOut = 0;

        for (int i = 0; i < 50; i++)
        {
            var benignLog = new TumLogEntry
            {
                EventName = "HTTP.HEALTH.POLL",
                Category = LogCategory.SystemDiagnostic,
                Severity = "Information",
                HttpMethod = "GET",
                StatusCode = 200,
                RequestPath = "/health"
            };

            var decision = governor.Evaluate(benignLog);
            if (decision.ShouldSampleOut) sampledOut++;
            else retained++;
        }

        // With 1-in-5 rate over 50 requests, exactly 10 should be retained and 40 sampled out
        Assert.Equal(10, retained);
        Assert.Equal(40, sampledOut);

        var stats = governor.GetStats();
        Assert.True(stats.IsSurgeActive);
        Assert.Equal(50, stats.TotalProcessed);
        Assert.Equal(10, stats.TotalRetained);
        Assert.Equal(40, stats.TotalSampledOut);
    }

    [Theory]
    [InlineData(401, "/api/login", "User.LoginFailed", LogCategory.SecurityThreat)]
    [InlineData(500, "/api/checkout", "Payment.Error", LogCategory.BusinessTransaction)]
    [InlineData(403, "/admin/settings", "Admin.Unauthorized", LogCategory.AuditTrail)]
    [InlineData(200, "/api/auth/token", "Token.Generated", LogCategory.LegalCompliance)]
    [InlineData(200, "/users/export", "PDPA.Export", LogCategory.PiiAccess)]
    public void Governor_InSurgeMode_Must_Never_Sample_Critical_Security_Or_Auth_Logs(
        int statusCode, string path, string eventName, LogCategory category)
    {
        var governor = new SmartSamplingGovernor();
        governor.Configure(forceSurge: true, surgeThresholdEps: 100, benignSampleRate: 100);

        for (int i = 0; i < 25; i++)
        {
            var criticalLog = new TumLogEntry
            {
                EventName = eventName,
                Category = category,
                Severity = statusCode >= 400 ? "Error" : "Information",
                HttpMethod = "POST",
                StatusCode = statusCode,
                RequestPath = path
            };

            var decision = governor.Evaluate(criticalLog);

            Assert.False(decision.ShouldSampleOut, $"Failed to retain critical log on attempt {i}");
            Assert.True(decision.IsCriticalSecurity);
            Assert.Equal(1, decision.SampleWeight);
        }

        var stats = governor.GetStats();
        Assert.Equal(25, stats.TotalCriticalRetained);
        Assert.Equal(0, stats.TotalSampledOut);
    }
}
