// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using Tum.Trust.Security.Core.Models.Sigma;

namespace Tum.Siem.Server.Services;

/// <summary>
/// Service contract for discovering, compiling, and managing Sigma detection rules.
/// </summary>
public interface ISigmaRuleLoaderService
{
    /// <summary>
    /// Loads all Sigma rules from the configured rules directory.
    /// </summary>
    int LoadAllRules();

    /// <summary>
    /// Registers and compiles a new Sigma rule from YAML definition.
    /// </summary>
    SigmaRule RegisterFromYaml(string yamlContent);

    /// <summary>
    /// Gets the absolute directory path where Sigma rules reside.
    /// </summary>
    string? ResolveRulesDirectory();
}
