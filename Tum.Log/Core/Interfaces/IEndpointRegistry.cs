// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Collections.Generic;
using Tum.Trust.Security.Core.Models.Logging;

namespace Tum.Trust.Security.Core.Interfaces.Logging
{
    /// <summary>
    /// Enterprise registry tracking discovered application API endpoints, their PII data flow profiles,
    /// and targeted attack frequencies.
    /// </summary>
    public interface IEndpointRegistry
    {
        /// <summary>
        /// Records or updates an endpoint invocation with PII and security threat telemetry.
        /// </summary>
        /// <param name="routePath">The HTTP route or endpoint path.</param>
        /// <param name="httpMethod">The HTTP method.</param>
        /// <param name="hasInboundPii">Whether inbound request carried PII.</param>
        /// <param name="hasOutboundPii">Whether outbound response carried PII.</param>
        /// <param name="piiTypes">The specific PII types detected.</param>
        /// <param name="hasThreat">Whether a security threat targeted this endpoint.</param>
        void RecordEndpointAccess(
            string routePath,
            string httpMethod,
            bool hasInboundPii,
            bool hasOutboundPii,
            IEnumerable<PiiType> piiTypes,
            bool hasThreat);

        /// <summary>
        /// Retrieves the comprehensive inventory of all cataloged API endpoints in the system.
        /// </summary>
        /// <returns>A read-only list of endpoint PII profiles.</returns>
        IReadOnlyList<EndpointPiiProfile> GetAllEndpoints();

        /// <summary>
        /// Retrieves the profile for a specific endpoint route.
        /// </summary>
        /// <param name="routePath">The route path.</param>
        /// <param name="httpMethod">The HTTP method.</param>
        /// <returns>The endpoint profile if discovered; otherwise null.</returns>
        EndpointPiiProfile? GetProfile(string routePath, string httpMethod);
    }
}
