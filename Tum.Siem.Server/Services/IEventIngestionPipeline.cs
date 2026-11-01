// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using Tum.Siem.Server.DTOs.Responses;
using Tum.Trust.Security.Core.Models.Logging;

namespace Tum.Siem.Server.Services;

/// <summary>
/// Pipeline orchestrator for ingesting, validating, threat-evaluating, and alerting on events.
/// </summary>
public interface IEventIngestionPipeline
{
    /// <summary>
    /// Processes an incoming log entry through PII masking, Sigma correlation, risk scoring, and alert dispatch.
    /// </summary>
    Task<IngestLogResponse> IngestAsync(TumLogEntry entry, CancellationToken cancellationToken = default);
}
