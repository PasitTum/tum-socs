// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Collections.Generic;
using System.Text.Json.Serialization;
using Tum.Trust.Security.Core.Models.Alerts;
using Tum.Trust.Security.Core.Models.Logging;
using Tum.Trust.Security.Core.Models.Risk;
using Tum.Trust.Security.Core.Models.Sigma;

namespace Tum.Trust.Security.Infrastructure.Serialization
{
    /// <summary>
    /// Source-generated, zero-reflection JSON serializer context fully compatible with .NET 8/10 Native AOT.
    /// Provides maximum throughput and eliminates runtime IL generation.
    /// </summary>
    [JsonSourceGenerationOptions(
        WriteIndented = false,
        GenerationMode = JsonSourceGenerationMode.Default,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonSerializable(typeof(TumLogEntry))]
    [JsonSerializable(typeof(List<TumLogEntry>))]
    [JsonSerializable(typeof(TumAuditExportBundle))]
    [JsonSerializable(typeof(TamperProofReceipt))]
    [JsonSerializable(typeof(PiiDetectionResult))]
    [JsonSerializable(typeof(SecurityThreatAlert))]
    [JsonSerializable(typeof(OutboundLeakDetection))]
    [JsonSerializable(typeof(SigmaMatchResult))]
    [JsonSerializable(typeof(List<SigmaMatchResult>))]
    [JsonSerializable(typeof(RiskScoreResult))]
    [JsonSerializable(typeof(AlertNotification))]
    [JsonSerializable(typeof(DiscordWebhookPayload))]
    [JsonSerializable(typeof(SlackWebhookPayload))]
    [JsonSerializable(typeof(GenericAlertWebhookPayload))]
    public partial class TumLogJsonSerializerContext : JsonSerializerContext
    {
    }

    /// <summary>
    /// Source-generated JSON serializer context with indented formatting for compliance exports.
    /// </summary>
    [JsonSourceGenerationOptions(
        WriteIndented = true,
        GenerationMode = JsonSourceGenerationMode.Default,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonSerializable(typeof(TumAuditExportBundle))]
    [JsonSerializable(typeof(TumLogEntry))]
    [JsonSerializable(typeof(List<TumLogEntry>))]
    public partial class TumLogIndentedJsonSerializerContext : JsonSerializerContext
    {
    }
}
