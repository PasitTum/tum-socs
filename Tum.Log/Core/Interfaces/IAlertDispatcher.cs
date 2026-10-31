// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Tum.Trust.Security.Core.Models.Alerts;

namespace Tum.Trust.Security.Core.Interfaces.Logging
{
    /// <summary>
    /// Contract for real-time security alert dispatching across Discord, Slack, and generic Webhooks.
    /// </summary>
    public interface IAlertDispatcher : IAsyncDisposable, IDisposable
    {
        /// <summary>
        /// Registers a destination channel for alert dispatches.
        /// </summary>
        /// <param name="channel">The channel configuration.</param>
        void RegisterChannel(AlertChannelConfig channel);

        /// <summary>
        /// Dispatches a high-priority security incident alert to configured notification channels.
        /// </summary>
        /// <param name="alert">The alert notification payload.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Count of channels successfully notified.</returns>
        Task<int> DispatchAlertAsync(AlertNotification alert, CancellationToken cancellationToken = default);
    }
}
