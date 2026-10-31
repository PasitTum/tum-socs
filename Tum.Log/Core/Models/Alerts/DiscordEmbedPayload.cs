// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace Tum.Trust.Security.Core.Models.Alerts
{
    /// <summary>
    /// Discord Embed field structure.
    /// </summary>
    public class DiscordEmbedField
    {
        [JsonPropertyName("name")]
        public string Name { get; set; } = string.Empty;

        [JsonPropertyName("value")]
        public string Value { get; set; } = string.Empty;

        [JsonPropertyName("inline")]
        public bool Inline { get; set; } = true;
    }

    /// <summary>
    /// Discord Embed footer structure.
    /// </summary>
    public class DiscordEmbedFooter
    {
        [JsonPropertyName("text")]
        public string Text { get; set; } = string.Empty;
    }

    /// <summary>
    /// Discord Embed object.
    /// </summary>
    public class DiscordEmbed
    {
        [JsonPropertyName("title")]
        public string Title { get; set; } = string.Empty;

        [JsonPropertyName("description")]
        public string Description { get; set; } = string.Empty;

        [JsonPropertyName("color")]
        public int Color { get; set; }

        [JsonPropertyName("timestamp")]
        public string Timestamp { get; set; } = string.Empty;

        [JsonPropertyName("fields")]
        public List<DiscordEmbedField> Fields { get; set; } = new List<DiscordEmbedField>();

        [JsonPropertyName("footer")]
        public DiscordEmbedFooter? Footer { get; set; }
    }

    /// <summary>
    /// Root payload sent to Discord Webhooks.
    /// </summary>
    public class DiscordWebhookPayload
    {
        [JsonPropertyName("username")]
        public string Username { get; set; } = "TUM-OpenSIEM Sentinel";

        [JsonPropertyName("embeds")]
        public List<DiscordEmbed> Embeds { get; set; } = new List<DiscordEmbed>();
    }
}
