// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Tum.Trust.Security.Core.Models.Alerts
{
    /// <summary>
    /// Supported alert notification destinations for TUM-OpenSIEM.
    /// </summary>
    public enum AlertChannelType
    {
        /// <summary>
        /// Generic HTTP POST Webhook JSON payload.
        /// </summary>
        GenericWebhook = 1,

        /// <summary>
        /// Discord Webhook with color-coded rich embeds.
        /// </summary>
        Discord = 2,

        /// <summary>
        /// Slack Incoming Webhook with Block Kit formatting.
        /// </summary>
        Slack = 3,

        /// <summary>
        /// Microsoft Teams incoming webhook connector.
        /// </summary>
        MicrosoftTeams = 4
    }
}
