// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Tum.Trust.Security.Core.Interfaces.Logging;
using Tum.Trust.Security.Core.Models.Logging;

namespace Tum.Trust.Security.Infrastructure.Logging
{
    /// <summary>
    /// Sovereign logging and compliance engine coordinating AI PII sanitization, bidirectional threat and leak defense,
    /// endpoint discovery mapping, and multi-sink tamper-proof WORM persistence.
    /// </summary>
    public class TumLogEngine : ITumLogEngine
    {
        private readonly ITumPiiSanitizer _piiSanitizer;
        private readonly ITumThreatDetector _threatDetector;
        private readonly IOutboundLeakDetector _outboundLeakDetector;
        private readonly ITamperProofLogStorage _storage;
        private readonly ILogSinkDispatcher _sinkDispatcher;
        private readonly IEndpointRegistry _endpointRegistry;
        private readonly TumLogOptions _options;
        private readonly ILogger<TumLogEngine> _logger;

        /// <inheritdoc />
        public IEndpointRegistry EndpointRegistry => _endpointRegistry;

        /// <summary>
        /// Initializes a new instance of the <see cref="TumLogEngine"/> class.
        /// </summary>
        /// <param name="piiSanitizer">The PII sanitizer component.</param>
        /// <param name="threatDetector">The threat detector component.</param>
        /// <param name="outboundLeakDetector">The outbound leak detector component.</param>
        /// <param name="storage">The tamper-proof storage component.</param>
        /// <param name="sinkDispatcher">The multi-destination sink dispatcher.</param>
        /// <param name="endpointRegistry">The endpoint and PII registry.</param>
        /// <param name="options">Configuration options.</param>
        /// <param name="logger">Optional logger instance.</param>
        public TumLogEngine(
            ITumPiiSanitizer? piiSanitizer = null,
            ITumThreatDetector? threatDetector = null,
            IOutboundLeakDetector? outboundLeakDetector = null,
            ITamperProofLogStorage? storage = null,
            ILogSinkDispatcher? sinkDispatcher = null,
            IEndpointRegistry? endpointRegistry = null,
            TumLogOptions? options = null,
            ILogger<TumLogEngine>? logger = null)
        {
            _options = options ?? new TumLogOptions();
            _piiSanitizer = piiSanitizer ?? new TumPiiSanitizer();
            _threatDetector = threatDetector ?? new TumThreatDetector();
            _outboundLeakDetector = outboundLeakDetector ?? new OutboundLeakDetector(_piiSanitizer, _options);
            _storage = storage ?? new TamperProofLogChain(_options);
            _sinkDispatcher = sinkDispatcher ?? new LogSinkDispatcher(_options, _storage);
            _endpointRegistry = endpointRegistry ?? new EndpointRegistry();
            _logger = logger ?? NullLogger<TumLogEngine>.Instance;
        }

        /// <inheritdoc />
        public async Task<TumLogEntry> LogAsync(TumLogEntry entry, CancellationToken cancellationToken = default)
        {
            if (entry == null)
            {
                throw new ArgumentNullException(nameof(entry));
            }

            // 1. Standardize Event Name & Action Taxonomy (ISO 27001 standard length limit)
            entry.EventName = StandardEventAction.Normalize(entry.EventName, _options.MaxEventNameLength);
            if (string.IsNullOrEmpty(entry.StandardAction) || entry.StandardAction == "GENERIC.EVENT")
            {
                entry.StandardAction = entry.EventName;
            }

            // 2. Correlation Tracking (Ensure Correlation ID is populated)
            if (string.IsNullOrEmpty(entry.CorrelationId))
            {
                entry.CorrelationId = Guid.NewGuid().ToString("N");
            }

            // Apply defense mode
            entry.DefenseModeApplied = _options.DefenseMode;

            // 3. Auto Inbound PII Sanitization
            bool inboundPiiFound = false;
            if (_options.EnableAutoPiiMasking && !string.IsNullOrEmpty(entry.PayloadSanitized))
            {
                var (sanitized, detections) = _piiSanitizer.SanitizeText(entry.PayloadSanitized);
                entry.PayloadSanitized = sanitized;
                entry.PiiRedactedCount = detections.Count;
                entry.RedactedDetails = detections;
                inboundPiiFound = detections.Count > 0;
            }

            // 4. Real-Time Inbound Threat Inspection
            bool threatFound = false;
            if (_options.EnableThreatDetection && _options.DefenseMode != ThreatDefenseMode.Disabled)
            {
                var threats = _threatDetector.InspectRequest(
                    entry.RequestPath,
                    entry.HttpMethod,
                    queryString: null,
                    entry.PayloadSanitized,
                    entry.ClientIp);

                if (threats.Count > 0)
                {
                    threatFound = true;
                    entry.SecurityThreats.AddRange(threats);
                    entry.Category = LogCategory.SecurityThreat;
                    entry.Severity = "Critical";

                    _logger.LogWarning("Security Threat detected in request from IP {ClientIp}: {ThreatCount} vector(s)",
                        entry.ClientIp, threats.Count);
                }
            }

            // 5. Automatic Endpoint Discovery & PII Mapping
            if (_options.TrackEndpointProfiles && !string.IsNullOrEmpty(entry.RequestPath))
            {
                var observedTypes = entry.RedactedDetails.Select(r => r.Type).ToList();
                bool outboundPii = entry.OutboundLeaks.Any(l => l.LeakType == OutboundLeakType.PiiLeakagePrevented);

                _endpointRegistry.RecordEndpointAccess(
                    entry.RequestPath,
                    entry.HttpMethod ?? "GET",
                    inboundPiiFound,
                    outboundPii,
                    observedTypes,
                    threatFound);
            }

            // 6. Stamp Application Metadata
            if (string.IsNullOrEmpty(entry.ApplicationName))
            {
                entry.ApplicationName = _options.ApplicationName;
            }

            if (string.IsNullOrEmpty(entry.Environment))
            {
                entry.Environment = _options.Environment;
            }

            // 7. Multi-Destination Dispatching (Local WORM, Syslog RFC 5424, OpenSearch, S3)
            var dispatched = await _sinkDispatcher.DispatchAsync(entry, cancellationToken).ConfigureAwait(false);
            entry.DispatchedSinks = dispatched;

            return entry;
        }

        /// <inheritdoc />
        public async Task<TumLogEntry> LogEventAsync(
            string eventName,
            LogCategory category,
            string payload,
            string? userId = null,
            string? clientIp = null,
            string severity = "Information",
            CancellationToken cancellationToken = default)
        {
            var entry = new TumLogEntry
            {
                EventName = eventName,
                Category = category,
                PayloadSanitized = payload ?? string.Empty,
                UserId = userId,
                ClientIp = clientIp ?? "127.0.0.1",
                Severity = severity,
                TimestampUtc = DateTimeOffset.UtcNow,
                StandardAction = StandardEventAction.Normalize(eventName, _options.MaxEventNameLength)
            };

            return await LogAsync(entry, cancellationToken).ConfigureAwait(false);
        }

        /// <inheritdoc />
        public Task<bool> VerifyIntegrityAsync(CancellationToken cancellationToken = default)
        {
            return _storage.VerifyChainIntegrityAsync(cancellationToken);
        }

        /// <inheritdoc />
        public async Task<IReadOnlyList<TumLogEntry>> GetLogsAsync(
            int count = 100,
            LogCategory? filterCategory = null,
            CancellationToken cancellationToken = default)
        {
            var list = await _storage.GetRecentEntriesAsync(count, cancellationToken).ConfigureAwait(false);
            if (!filterCategory.HasValue)
            {
                return list;
            }

            var filtered = new List<TumLogEntry>();
            foreach (var item in list)
            {
                if (item.Category == filterCategory.Value)
                {
                    filtered.Add(item);
                }
            }
            return filtered.AsReadOnly();
        }
    }
}
