// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Tum.Trust.Security.Core.Interfaces.Logging;
using Tum.Trust.Security.Core.Models.Alerts;
using Tum.Trust.Security.Core.Models.Risk;
using Tum.Trust.Security.Infrastructure.Serialization;

namespace Tum.Trust.Security.Infrastructure.Alerts
{
    /// <summary>
    /// Real-time multi-channel Alert Dispatcher routing threat notifications to Discord, Slack, and Webhooks.
    /// Engineered for asynchronous execution with zero impact on log ingestion pipelines.
    /// Fully Native AOT compatible with zero-reflection JSON serialization.
    /// </summary>
    public class AlertDispatcher : IAlertDispatcher
    {
        private readonly List<AlertChannelConfig> _channels = new();
        private readonly HttpClient _httpClient;
        private readonly bool _ownsHttpClient;
        private readonly ILogger<AlertDispatcher> _logger;
        private readonly object _lock = new();

        /// <summary>
        /// Initializes a new instance of the <see cref="AlertDispatcher"/> class.
        /// </summary>
        /// <param name="channels">Optional list of initial channel configurations.</param>
        /// <param name="httpClient">Optional pre-configured HttpClient instance.</param>
        /// <param name="logger">Optional logger instance.</param>
        public AlertDispatcher(
            IEnumerable<AlertChannelConfig>? channels = null,
            HttpClient? httpClient = null,
            ILogger<AlertDispatcher>? logger = null)
        {
            _logger = logger ?? NullLogger<AlertDispatcher>.Instance;

            if (httpClient != null)
            {
                _httpClient = httpClient;
                _ownsHttpClient = false;
            }
            else
            {
                _httpClient = new HttpClient { Timeout = TimeSpan.FromSeconds(5) };
                _ownsHttpClient = true;
            }

            if (channels != null)
            {
                _channels.AddRange(channels);
            }
        }

        /// <inheritdoc />
        public void RegisterChannel(AlertChannelConfig channel)
        {
            if (channel == null) throw new ArgumentNullException(nameof(channel));
            lock (_lock)
            {
                _channels.Add(channel);
            }
        }

        /// <inheritdoc />
        public async Task<int> DispatchAlertAsync(AlertNotification alert, CancellationToken cancellationToken = default)
        {
            if (alert == null) throw new ArgumentNullException(nameof(alert));

            List<AlertChannelConfig> activeChannels;
            lock (_lock)
            {
                activeChannels = new List<AlertChannelConfig>(_channels);
            }

            int dispatchedCount = 0;

            for (int i = 0; i < activeChannels.Count; i++)
            {
                var ch = activeChannels[i];
                if (!ch.IsEnabled || alert.RiskScore < ch.MinimumRiskScore)
                {
                    continue;
                }

                try
                {
                    string jsonPayload = FormatPayloadForChannel(alert, ch.ChannelType);
                    using var content = new StringContent(jsonPayload, Encoding.UTF8, "application/json");

                    if (!string.IsNullOrEmpty(ch.AuthToken))
                    {
                        content.Headers.Add("Authorization", ch.AuthToken.StartsWith("Bearer ") ? ch.AuthToken : $"Bearer {ch.AuthToken}");
                    }

                    var response = await _httpClient.PostAsync(ch.WebhookUrl, content, cancellationToken).ConfigureAwait(false);
                    if (response.IsSuccessStatusCode)
                    {
                        dispatchedCount++;
                        _logger.LogInformation("Dispatched alert {AlertId} to {ChannelType} successfully", alert.AlertId, ch.ChannelType);
                    }
                    else
                    {
                        string err = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
                        _logger.LogWarning("Failed to dispatch alert {AlertId} to {ChannelType} (HTTP {StatusCode}): {Error}",
                            alert.AlertId, ch.ChannelType, response.StatusCode, err);
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Exception dispatching alert {AlertId} to channel {ChannelType}: {Message}",
                        alert.AlertId, ch.ChannelType, ex.Message);
                }
            }

            return dispatchedCount;
        }

        /// <summary>
        /// Formats an alert notification for the specified channel payload schema.
        /// </summary>
        public static string FormatPayloadForChannel(AlertNotification alert, AlertChannelType channelType)
        {
            return channelType switch
            {
                AlertChannelType.Discord => FormatDiscordEmbed(alert),
                AlertChannelType.Slack => FormatSlackBlockKit(alert),
                _ => FormatGenericWebhook(alert)
            };
        }

        private static string FormatDiscordEmbed(AlertNotification alert)
        {
            int color = alert.SeverityBand switch
            {
                RiskSeverityBand.Critical => 0xE74C3C, // Red
                RiskSeverityBand.High => 0xE67E22,     // Orange
                RiskSeverityBand.Medium => 0xF1C40F,   // Yellow
                _ => 0x2ECC71                          // Green
            };

            string mitreStr = alert.MitreTechniques.Count > 0
                ? string.Join(", ", alert.MitreTechniques)
                : "None";

            var payload = new DiscordWebhookPayload
            {
                Username = "TUM-OpenSIEM Sentinel",
                Embeds = new List<DiscordEmbed>
                {
                    new DiscordEmbed
                    {
                        Title = $"🚨 [{alert.SeverityBand.ToString().ToUpperInvariant()}] {alert.Title}",
                        Description = alert.Description,
                        Color = color,
                        Timestamp = alert.TimestampUtc.ToString("o"),
                        Fields = new List<DiscordEmbedField>
                        {
                            new DiscordEmbedField { Name = "Risk Score", Value = $"{alert.RiskScore:F1} / 100", Inline = true },
                            new DiscordEmbedField { Name = "Severity", Value = alert.SeverityBand.ToString(), Inline = true },
                            new DiscordEmbedField { Name = "Client IP", Value = $"`{alert.ClientIp}`", Inline = true },
                            new DiscordEmbedField { Name = "Environment", Value = alert.Environment, Inline = true },
                            new DiscordEmbedField { Name = "MITRE ATT&CK", Value = mitreStr, Inline = true },
                            new DiscordEmbedField { Name = "Standard Action", Value = alert.StandardAction, Inline = true }
                        },
                        Footer = new DiscordEmbedFooter
                        {
                            Text = $"Alert ID: {alert.AlertId} | TUM Sovereign Security"
                        }
                    }
                }
            };

            return JsonSerializer.Serialize(payload, TumLogJsonSerializerContext.Default.DiscordWebhookPayload);
        }

        private static string FormatSlackBlockKit(AlertNotification alert)
        {
            string mitreStr = alert.MitreTechniques.Count > 0
                ? string.Join(", ", alert.MitreTechniques)
                : "None";

            var payload = new SlackWebhookPayload
            {
                Text = $"🚨 [{alert.SeverityBand}] {alert.Title}",
                Blocks = new List<SlackBlock>
                {
                    new SlackBlock
                    {
                        BlockType = "header",
                        Text = new SlackTextElement
                        {
                            ElementType = "plain_text",
                            Text = $"🚨 {alert.Title}",
                            Emoji = true
                        }
                    },
                    new SlackBlock
                    {
                        BlockType = "section",
                        Text = new SlackTextElement
                        {
                            ElementType = "mrkdwn",
                            Text = $"*{alert.Description}*\n\n" +
                                   $"• *Risk Score:* `{alert.RiskScore:F1} / 100` ({alert.SeverityBand})\n" +
                                   $"• *Client IP:* `{alert.ClientIp}`\n" +
                                   $"• *MITRE ATT&CK:* `{mitreStr}`\n" +
                                   $"• *Environment:* `{alert.Environment}`"
                        }
                    },
                    new SlackBlock
                    {
                        BlockType = "context",
                        Elements = new List<SlackTextElement>
                        {
                            new SlackTextElement
                            {
                                ElementType = "mrkdwn",
                                Text = $"App: *{alert.ApplicationName}* | Alert ID: `{alert.AlertId}` | Timestamp: {alert.TimestampUtc:u}"
                            }
                        }
                    }
                }
            };

            return JsonSerializer.Serialize(payload, TumLogJsonSerializerContext.Default.SlackWebhookPayload);
        }

        private static string FormatGenericWebhook(AlertNotification alert)
        {
            var payload = new GenericAlertWebhookPayload
            {
                AlertId = alert.AlertId,
                Title = alert.Title,
                Description = alert.Description,
                RiskScore = alert.RiskScore,
                SeverityBand = alert.SeverityBand.ToString(),
                TimestampUtc = alert.TimestampUtc,
                ClientIp = alert.ClientIp,
                ApplicationName = alert.ApplicationName,
                Environment = alert.Environment,
                StandardAction = alert.StandardAction,
                MitreTechniques = alert.MitreTechniques
            };

            return JsonSerializer.Serialize(payload, TumLogJsonSerializerContext.Default.GenericAlertWebhookPayload);
        }

        /// <inheritdoc />
        public void Dispose()
        {
            if (_ownsHttpClient)
            {
                _httpClient.Dispose();
            }
            GC.SuppressFinalize(this);
        }

        /// <inheritdoc />
        public ValueTask DisposeAsync()
        {
            Dispose();
            return ValueTask.CompletedTask;
        }
    }
}
