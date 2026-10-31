// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace Tum.Trust.Security.Core.Models.Alerts
{
    public class SlackTextElement
    {
        [JsonPropertyName("type")]
        public string ElementType { get; set; } = "mrkdwn";

        [JsonPropertyName("text")]
        public string Text { get; set; } = string.Empty;

        [JsonPropertyName("emoji")]
        public bool? Emoji { get; set; }
    }

    public class SlackBlock
    {
        [JsonPropertyName("type")]
        public string BlockType { get; set; } = "section";

        [JsonPropertyName("text")]
        public SlackTextElement? Text { get; set; }

        [JsonPropertyName("elements")]
        public List<SlackTextElement>? Elements { get; set; }
    }

    public class SlackWebhookPayload
    {
        [JsonPropertyName("text")]
        public string Text { get; set; } = string.Empty;

        [JsonPropertyName("blocks")]
        public List<SlackBlock> Blocks { get; set; } = new List<SlackBlock>();
    }

    public class GenericAlertWebhookPayload
    {
        [JsonPropertyName("alertId")]
        public string AlertId { get; set; } = string.Empty;

        [JsonPropertyName("title")]
        public string Title { get; set; } = string.Empty;

        [JsonPropertyName("description")]
        public string Description { get; set; } = string.Empty;

        [JsonPropertyName("riskScore")]
        public double RiskScore { get; set; }

        [JsonPropertyName("severityBand")]
        public string SeverityBand { get; set; } = string.Empty;

        [JsonPropertyName("timestampUtc")]
        public DateTimeOffset TimestampUtc { get; set; }

        [JsonPropertyName("clientIp")]
        public string ClientIp { get; set; } = string.Empty;

        [JsonPropertyName("applicationName")]
        public string ApplicationName { get; set; } = string.Empty;

        [JsonPropertyName("environment")]
        public string Environment { get; set; } = string.Empty;

        [JsonPropertyName("standardAction")]
        public string StandardAction { get; set; } = string.Empty;

        [JsonPropertyName("mitreTechniques")]
        public List<string> MitreTechniques { get; set; } = new List<string>();
    }
}
