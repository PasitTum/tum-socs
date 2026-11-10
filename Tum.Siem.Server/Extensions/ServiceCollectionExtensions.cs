// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using Microsoft.OpenApi.Models;
using Tum.Log;
using Tum.Siem.Server.Configuration;
using Tum.Siem.Server.Services;
using Tum.Trust.Security.Core.Interfaces.Logging;
using Tum.Trust.Security.Core.Models.Logging;
using Tum.Trust.Security.Infrastructure.Analytics;
using Tum.Trust.Security.Infrastructure.Query;

namespace Tum.Siem.Server.Extensions;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddSiemInfrastructure(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        // 1. Strongly typed options
        var siemSection = configuration.GetSection(SiemServerOptions.SectionName);
        services.Configure<SiemServerOptions>(siemSection);
        var siemOptions = siemSection.Get<SiemServerOptions>() ?? new SiemServerOptions();

        // 2. Add OpenSIEM / TumLog Core
        services.AddTumLog(opts =>
        {
            opts.ApplicationName = siemOptions.ApplicationName;
            opts.Environment = siemOptions.Environment;
            opts.EnableAutoPiiMasking = siemOptions.EnableAutoPiiMasking;
            opts.EnableThreatDetection = siemOptions.EnableThreatDetection;
            opts.EnableMerkleChaining = siemOptions.EnableMerkleChaining;
            opts.WormRetentionDays = siemOptions.WormRetentionDays;
            opts.StorageDirectory = Path.IsPathRooted(siemOptions.StorageDirectory)
                ? siemOptions.StorageDirectory
                : Path.Combine(AppContext.BaseDirectory, siemOptions.StorageDirectory);
            opts.NtpServerHost = siemOptions.NtpServerHost;
        });

        // 3. Analytics & Query Engines
        services.AddSingleton<IEventQueryEngine, EventQueryEngine>();
        services.AddSingleton<IThreatAnalyticsEngine, ThreatAnalyticsEngine>();

        // 4. Server-level Domain Services
        services.AddSingleton<IAuthService, AuthService>();
        services.AddSingleton<ISigmaRuleLoaderService, SigmaRuleLoaderService>();
        services.AddSingleton<IDigitalReceiptService, DigitalReceiptService>();
        services.AddSingleton<IEbpfFileTracingService, EbpfFileTracingService>();
        services.AddSingleton<ISmartSamplingGovernor, SmartSamplingGovernor>();
        services.AddSingleton<IDeploymentGeneratorService, DeploymentGeneratorService>();
        services.AddSingleton<IHostTelemetryService, HostTelemetryService>();
        services.AddSingleton<IInfraOrchestratorService, InfraOrchestratorService>();
        services.AddSingleton<ILoadTestHarnessService, LoadTestHarnessService>();
        services.AddScoped<IEventIngestionPipeline, EventIngestionPipeline>();
        services.AddScoped<IDatasetIngestionService, DatasetIngestionService>();

        // 5. Controllers & Web API
        services.AddControllers()
            .AddJsonOptions(options =>
            {
                options.JsonSerializerOptions.PropertyNamingPolicy = System.Text.Json.JsonNamingPolicy.CamelCase;
            });

        // 6. Swagger / OpenAPI Documentation
        services.AddEndpointsApiExplorer();
        services.AddSwaggerGen(c =>
        {
            c.SwaggerDoc("v1", new OpenApiInfo
            {
                Title = "TUM-SOC Platform API (Phase 1: SIEM Core)",
                Version = "v2.0",
                Description = "Sovereign Enterprise SOC Platform - Phase 1: Real-time SIEM & Security Mesh (Thai CCA Sec 26 & ISO 27001 compliant)",
                Contact = new OpenApiContact
                {
                    Name = "TUM Trust Security Engineering",
                    Url = new Uri("https://tum.trustsecurity.io")
                }
            });

            c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
            {
                Description = "Enter JWT / Sovereign Bearer token (e.g. 'Bearer {token}')",
                Name = "Authorization",
                In = ParameterLocation.Header,
                Type = SecuritySchemeType.ApiKey,
                Scheme = "Bearer"
            });

            c.AddSecurityRequirement(new OpenApiSecurityRequirement
            {
                {
                    new OpenApiSecurityScheme
                    {
                        Reference = new OpenApiReference
                        {
                            Type = ReferenceType.SecurityScheme,
                            Id = "Bearer"
                        }
                    },
                    Array.Empty<string>()
                }
            });
        });

        // 7. CORS
        services.AddCors(opts =>
        {
            opts.AddDefaultPolicy(p =>
            {
                if (siemOptions.CorsOrigins != null && siemOptions.CorsOrigins.Contains("*"))
                {
                    p.AllowAnyOrigin().AllowAnyHeader().AllowAnyMethod();
                }
                else if (siemOptions.CorsOrigins != null && siemOptions.CorsOrigins.Length > 0)
                {
                    p.WithOrigins(siemOptions.CorsOrigins)
                     .AllowAnyHeader()
                     .AllowAnyMethod()
                     .AllowCredentials();
                }
                else
                {
                    p.AllowAnyOrigin().AllowAnyHeader().AllowAnyMethod();
                }
            });
        });

        // 8. Health Checks
        services.AddHealthChecks();

        return services;
    }
}
