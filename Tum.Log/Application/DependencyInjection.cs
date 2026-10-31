// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Tum.Trust.Security.Core.Interfaces.Logging;
using Tum.Trust.Security.Core.Models.Logging;
using Tum.Trust.Security.Infrastructure.Logging;

namespace Tum.Log
{
    /// <summary>
    /// Extension methods for setting up TUMLog sovereign application compliance and threat defense logging in an <see cref="IServiceCollection"/>.
    /// </summary>
    public static class DependencyInjection
    {
        /// <summary>
        /// Registers TUMLog Application-Layer Logging, AI PII Sanitization, Threat Detection, and
        /// Thai Computer Crime Act Section 26 90-day WORM Merkle chain compliance engine.
        /// </summary>
        /// <param name="services">The service collection.</param>
        /// <param name="configure">Optional configuration callback.</param>
        /// <returns>The service collection for chaining.</returns>
        public static IServiceCollection AddTumLog(
            this IServiceCollection services,
            Action<TumLogOptions>? configure = null)
        {
            if (services is null)
            {
                throw new ArgumentNullException(nameof(services));
            }

            var options = new TumLogOptions();
            configure?.Invoke(options);

            services.TryAddSingleton(options);
            services.TryAddSingleton<ITumPiiSanitizer, TumPiiSanitizer>();
            services.TryAddSingleton<ITumThreatDetector, TumThreatDetector>();
            services.TryAddSingleton<IOutboundLeakDetector, OutboundLeakDetector>();
            services.TryAddSingleton<IEndpointRegistry, EndpointRegistry>();
            services.TryAddSingleton<ITamperProofLogStorage, TamperProofLogChain>();
            services.TryAddSingleton<ILogSinkDispatcher, LogSinkDispatcher>();
            services.TryAddSingleton<ITumLogEngine, TumLogEngine>();

            return services;
        }
    }
}
