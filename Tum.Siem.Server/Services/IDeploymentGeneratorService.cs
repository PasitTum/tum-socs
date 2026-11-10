// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using Tum.Siem.Server.DTOs.Requests;
using Tum.Siem.Server.DTOs.Responses;

namespace Tum.Siem.Server.Services;

public interface IDeploymentGeneratorService
{
    /// <summary>
    /// Generates structured deployment manifests and architecture blueprints for the requested scale tier.
    /// </summary>
    DeploymentBundleResponse GenerateBundle(DeploymentConfigDto config);

    /// <summary>
    /// Packages all generated manifests, configurations, and bootstrap scripts into an in-memory ZIP archive.
    /// </summary>
    Task<byte[]> GenerateZipArchiveAsync(DeploymentConfigDto config);
}
