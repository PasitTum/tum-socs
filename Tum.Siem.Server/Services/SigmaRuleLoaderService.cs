// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Tum.Siem.Server.Configuration;
using Tum.Trust.Security.Core.Interfaces.Logging;
using Tum.Trust.Security.Core.Models.Sigma;
using Tum.Trust.Security.Infrastructure.Sigma;

namespace Tum.Siem.Server.Services;

/// <summary>
/// Production service for discovering, compiling, and registering SigmaHQ rules.
/// </summary>
public sealed class SigmaRuleLoaderService : ISigmaRuleLoaderService
{
    private readonly ISigmaRuleEngine _sigmaEngine;
    private readonly SiemServerOptions _options;
    private readonly ILogger<SigmaRuleLoaderService> _logger;

    public SigmaRuleLoaderService(
        ISigmaRuleEngine sigmaEngine,
        IOptions<SiemServerOptions> options,
        ILogger<SigmaRuleLoaderService> logger)
    {
        _sigmaEngine = sigmaEngine ?? throw new ArgumentNullException(nameof(sigmaEngine));
        _options = options?.Value ?? new SiemServerOptions();
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    public int LoadAllRules()
    {
        string? rulesDir = ResolveRulesDirectory();
        if (rulesDir == null || !Directory.Exists(rulesDir))
        {
            _logger.LogWarning("Sigma rules directory not found at configured path '{RulesDir}'. Operating with zero default rules.", _options.RulesDirectory);
            return 0;
        }

        _logger.LogInformation("Discovering and compiling Sigma rules from: {RulesDir}", rulesDir);
        var yamlFiles = Directory.GetFiles(rulesDir, "*.yml", SearchOption.AllDirectories)
            .Concat(Directory.GetFiles(rulesDir, "*.yaml", SearchOption.AllDirectories))
            .Distinct()
            .ToArray();

        int loadedCount = 0;
        foreach (var file in yamlFiles)
        {
            try
            {
                string yaml = File.ReadAllText(file);
                var rule = SigmaRuleParser.ParseYaml(yaml);
                _sigmaEngine.RegisterRule(rule);
                loadedCount++;
                _logger.LogDebug("Compiled Sigma rule '{Title}' ({Id}) from {File}", rule.Title, rule.Id, Path.GetFileName(file));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to compile Sigma rule file: {File}", file);
            }
        }

        _logger.LogInformation("Successfully compiled and activated {LoadedCount} Sigma detection rules (Total active: {ActiveCount})",
            loadedCount, _sigmaEngine.ActiveRuleCount);

        return loadedCount;
    }

    public SigmaRule RegisterFromYaml(string yamlContent)
    {
        if (string.IsNullOrWhiteSpace(yamlContent))
        {
            throw new ArgumentException("YAML rule definition cannot be empty.", nameof(yamlContent));
        }

        var rule = SigmaRuleParser.ParseYaml(yamlContent);
        _sigmaEngine.RegisterRule(rule);
        _logger.LogInformation("Dynamically registered Sigma rule '{Title}' ({Id})", rule.Title, rule.Id);
        return rule;
    }

    public string? ResolveRulesDirectory()
    {
        string configured = _options.RulesDirectory;
        if (Path.IsPathRooted(configured) && Directory.Exists(configured))
        {
            return configured;
        }

        var searchRoots = new[]
        {
            Directory.GetCurrentDirectory(),
            AppContext.BaseDirectory,
            AppDomain.CurrentDomain.BaseDirectory
        };

        foreach (var root in searchRoots)
        {
            if (string.IsNullOrEmpty(root)) continue;

            var dir = new DirectoryInfo(root);
            while (dir != null)
            {
                string candidate = Path.Combine(dir.FullName, configured);
                if (Directory.Exists(candidate))
                {
                    return candidate;
                }
                dir = dir.Parent;
            }
        }

        return null;
    }
}
