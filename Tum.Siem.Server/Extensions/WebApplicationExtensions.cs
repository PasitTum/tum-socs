// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using Tum.Siem.Server.Middleware;
using Tum.Siem.Server.Services;

namespace Tum.Siem.Server.Extensions;

public static class WebApplicationExtensions
{
    public static WebApplication UseSiemPipeline(this WebApplication app)
    {
        // 1. Global Exception Shielding & Security Headers
        app.UseMiddleware<GlobalExceptionMiddleware>();
        app.UseMiddleware<SecurityHeadersMiddleware>();

        // 2. Swagger / OpenAPI Documentation
        app.UseSwagger();
        app.UseSwaggerUI(c =>
        {
            c.SwaggerEndpoint("/swagger/v1/swagger.json", "TUM-SOC Core v2.0 (SIEM Edition)");
            c.RoutePrefix = "swagger";
            c.DocumentTitle = "TUM-SOC Platform API Explorer (SIEM Core)";
        });

        // 3. CORS
        app.UseCors();

        // 4. Static Files for modern SPA frontend (React / Vite)
        app.UseDefaultFiles();
        app.UseStaticFiles();

        // 5. Health Checks
        app.MapHealthChecks("/health");

        // 6. Controllers
        app.MapControllers();

        // 7. SPA Fallback routing
        app.MapFallback(async context =>
        {
            // If request is under /api, do not fallback to index.html
            if (context.Request.Path.StartsWithSegments("/api"))
            {
                context.Response.StatusCode = StatusCodes.Status404NotFound;
                return;
            }

            // Check if SPA index.html exists in wwwroot or visualizers fallback
            string wwwrootIndex = Path.Combine(app.Environment.WebRootPath ?? Path.Combine(AppContext.BaseDirectory, "wwwroot"), "index.html");
            if (File.Exists(wwwrootIndex))
            {
                context.Response.ContentType = "text/html; charset=utf-8";
                await context.Response.SendFileAsync(wwwrootIndex);
                return;
            }

            // Fallback to visualizers/index.html if available
            string? fallbackHtml = FindFallbackVisualizer();
            if (fallbackHtml != null && File.Exists(fallbackHtml))
            {
                context.Response.ContentType = "text/html; charset=utf-8";
                await context.Response.SendFileAsync(fallbackHtml);
                return;
            }

            context.Response.ContentType = "text/html; charset=utf-8";
            await context.Response.WriteAsync("<h1>TUM-OpenSIEM Core Online</h1><p>Web console bundle not found. Please build frontend or place static assets in wwwroot.</p>");
        });

        // 8. Auto-load Sigma Detection Rules
        using (var scope = app.Services.CreateScope())
        {
            var ruleLoader = scope.ServiceProvider.GetRequiredService<ISigmaRuleLoaderService>();
            ruleLoader.LoadAllRules();
        }

        return app;
    }

    private static string? FindFallbackVisualizer()
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

        return null;
    }
}
