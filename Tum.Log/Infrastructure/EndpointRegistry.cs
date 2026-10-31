// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using Tum.Trust.Security.Core.Interfaces.Logging;
using Tum.Trust.Security.Core.Models.Logging;

namespace Tum.Trust.Security.Infrastructure.Logging
{
    /// <summary>
    /// Thread-safe enterprise registry tracking discovered application API routes,
    /// mapping where sensitive PII flows and cataloging targeted threat attempts.
    /// </summary>
    public class EndpointRegistry : IEndpointRegistry
    {
        private readonly ConcurrentDictionary<string, EndpointPiiProfile> _endpoints = new();

        /// <inheritdoc />
        public void RecordEndpointAccess(
            string routePath,
            string httpMethod,
            bool hasInboundPii,
            bool hasOutboundPii,
            IEnumerable<PiiType> piiTypes,
            bool hasThreat)
        {
            if (string.IsNullOrWhiteSpace(routePath))
            {
                return;
            }

            string method = string.IsNullOrWhiteSpace(httpMethod) ? "GET" : httpMethod.ToUpperInvariant();
            string key = $"{method}:{routePath.Trim().ToLowerInvariant()}";

            _endpoints.AddOrUpdate(
                key,
                addValueFactory: _ =>
                {
                    var profile = new EndpointPiiProfile
                    {
                        RoutePath = routePath,
                        HttpMethod = method,
                        FirstSeenUtc = DateTimeOffset.UtcNow,
                        LastAccessedUtc = DateTimeOffset.UtcNow,
                        TotalInvocationCount = 1,
                        InboundPiiDetected = hasInboundPii,
                        OutboundPiiDetected = hasOutboundPii,
                        ThreatAttemptsCount = hasThreat ? 1 : 0
                    };

                    if (piiTypes != null)
                    {
                        foreach (var t in piiTypes)
                        {
                            profile.ObservedPiiTypes.Add(t);
                        }
                    }

                    return profile;
                },
                updateValueFactory: (_, existing) =>
                {
                    lock (existing)
                    {
                        existing.TotalInvocationCount++;
                        existing.LastAccessedUtc = DateTimeOffset.UtcNow;

                        if (hasInboundPii) existing.InboundPiiDetected = true;
                        if (hasOutboundPii) existing.OutboundPiiDetected = true;
                        if (hasThreat) existing.ThreatAttemptsCount++;

                        if (piiTypes != null)
                        {
                            foreach (var t in piiTypes)
                            {
                                existing.ObservedPiiTypes.Add(t);
                            }
                        }
                    }
                    return existing;
                });
        }

        /// <inheritdoc />
        public IReadOnlyList<EndpointPiiProfile> GetAllEndpoints()
        {
            return _endpoints.Values.OrderByDescending(e => e.LastAccessedUtc).ToList().AsReadOnly();
        }

        /// <inheritdoc />
        public EndpointPiiProfile? GetProfile(string routePath, string httpMethod)
        {
            if (string.IsNullOrWhiteSpace(routePath))
            {
                return null;
            }

            string method = string.IsNullOrWhiteSpace(httpMethod) ? "GET" : httpMethod.ToUpperInvariant();
            string key = $"{method}:{routePath.Trim().ToLowerInvariant()}";

            return _endpoints.TryGetValue(key, out var profile) ? profile : null;
        }
    }
}
