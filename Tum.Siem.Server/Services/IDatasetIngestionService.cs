// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using Tum.Siem.Server.DTOs.Requests;
using Tum.Siem.Server.DTOs.Responses;

namespace Tum.Siem.Server.Services;

/// <summary>
/// Service contract for loading realistic security telemetry datasets and executing production clean resets.
/// </summary>
public interface IDatasetIngestionService
{
    /// <summary>
    /// Gets catalog of available authentic security datasets.
    /// </summary>
    DatasetCatalogResponse GetCatalog();

    /// <summary>
    /// Ingests selected real-world attack logs into the SIEM pipeline.
    /// </summary>
    Task<DatasetOperationResult> LoadDatasetAsync(LoadDatasetRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// Purges all test telemetry and returns system to clean Genesis state for customer deployment.
    /// </summary>
    Task<DatasetOperationResult> PurgeAllDataAsync(CancellationToken cancellationToken = default);
}
