// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Tum.Trust.Security.Core.Models.Alerts
{
    /// <summary>
    /// Configuration for an external alert dispatch channel (Discord, Slack, Webhook).
    /// </summary>
    public class AlertChannelConfig
    {
        /// <summary>
        /// Gets or sets the target channel type.
        /// </summary>
        public AlertChannelType ChannelType { get; set; } = AlertChannelType.GenericWebhook;

        /// <summary>
        /// Gets or sets the target HTTP webhook endpoint URL.
        /// </summary>
        public string WebhookUrl { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets an optional authorization token or secret key.
        /// </summary>
        public string? AuthToken { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether this alert channel is active.
        /// </summary>
        public bool IsEnabled { get; set; } = true;

        /// <summary>
        /// Minimum risk score required to dispatch alerts to this channel (default: 70.0).
        /// </summary>
        public double MinimumRiskScore { get; set; } = 70.0;
    }
}
