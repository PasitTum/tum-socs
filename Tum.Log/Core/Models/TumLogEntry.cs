// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using System.Collections.Generic;

namespace Tum.Trust.Security.Core.Models.Logging
{
    /// <summary>
    /// Represents a sovereign, tamper-proof, PII-sanitized application-layer log entry conforming
    /// to the Thai Computer Crime Act B.E. 2560 Section 26 and PDPA regulations.
    /// </summary>
    public class TumLogEntry
    {
        /// <summary>
        /// Gets or sets the globally unique identifier for this log entry.
        /// </summary>
        public string LogId { get; set; } = Guid.NewGuid().ToString("N");

        /// <summary>
        /// Gets or sets the high-precision UTC timestamp synchronized via NTP Stratum 1.
        /// </summary>
        public DateTimeOffset TimestampUtc { get; set; } = DateTimeOffset.UtcNow;

        /// <summary>
        /// Gets or sets the developer-defined event name (e.g. 'User.Login', 'Payment.Processed', 'Identity.Verified').
        /// </summary>
        public string EventName { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the functional category of the log.
        /// </summary>
        public LogCategory Category { get; set; } = LogCategory.AuditTrail;

        /// <summary>
        /// Gets or sets the severity level ('Trace', 'Debug', 'Information', 'Warning', 'Error', 'Critical').
        /// </summary>
        public string Severity { get; set; } = "Information";

        /// <summary>
        /// Gets or sets the name of the originating application.
        /// </summary>
        public string ApplicationName { get; set; } = "TUM-Application";

        /// <summary>
        /// Gets or sets the deployment environment ('Production', 'Staging', 'Development').
        /// </summary>
        public string Environment { get; set; } = "Production";

        /// <summary>
        /// Gets or sets the subject or user identifier performing the action.
        /// </summary>
        public string? UserId { get; set; }

        /// <summary>
        /// Gets or sets the client IP address (IPv4 / IPv6) as required by Section 26.
        /// </summary>
        public string ClientIp { get; set; } = "127.0.0.1";

        /// <summary>
        /// Gets or sets the HTTP request path or API endpoint route.
        /// </summary>
        public string? RequestPath { get; set; }

        /// <summary>
        /// Gets or sets the HTTP method ('GET', 'POST', 'PUT', 'DELETE', etc.).
        /// </summary>
        public string? HttpMethod { get; set; }

        /// <summary>
        /// Gets or sets the HTTP response status code or operation outcome code.
        /// </summary>
        public int? StatusCode { get; set; }

        /// <summary>
        /// Gets or sets the execution duration of the request or operation in milliseconds.
        /// </summary>
        public double ExecutionDurationMs { get; set; }

        /// <summary>
        /// Gets or sets the fully sanitized and PII-redacted payload or message content.
        /// </summary>
        public string PayloadSanitized { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the count of Personal Identifiable Information (PII) elements masked in this entry.
        /// </summary>
        public int PiiRedactedCount { get; set; }

        /// <summary>
        /// Gets or sets the list of specific PII redactions performed.
        /// </summary>
        public List<PiiDetectionResult> RedactedDetails { get; set; } = new List<PiiDetectionResult>();

        /// <summary>
        /// Gets or sets the list of active security threats detected during ingestion of this event.
        /// </summary>
        public List<SecurityThreatAlert> SecurityThreats { get; set; } = new List<SecurityThreatAlert>();

        /// <summary>
        /// Gets or sets the cryptographic SHA-256 hash of this entry's sanitized content.
        /// </summary>
        public string TamperProofHash { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the cryptographic SHA-256 hash of the previous log entry in the immutable chain.
        /// </summary>
        public string PreviousEntryHash { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the Merkle root hash linking this log entry to the global verification tree.
        /// </summary>
        public string MerkleRoot { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the W3C TraceContext or GUID correlation ID tracking this request end-to-end across services.
        /// </summary>
        public string CorrelationId { get; set; } = Guid.NewGuid().ToString("N");

        /// <summary>
        /// Gets or sets the normalized standard action taxonomy conforming to ISO 27001 (e.g. 'AUTH.LOGIN', 'DATA.READ').
        /// </summary>
        public string StandardAction { get; set; } = "GENERIC.EVENT";

        /// <summary>
        /// Gets or sets the list of sensitive data exfiltrations or leaks intercepted on outbound response egress.
        /// </summary>
        public List<OutboundLeakDetection> OutboundLeaks { get; set; } = new List<OutboundLeakDetection>();

        /// <summary>
        /// Gets or sets the list of storage destination sinks to which this entry was successfully dispatched.
        /// </summary>
        public List<StorageSinkType> DispatchedSinks { get; set; } = new List<StorageSinkType> { StorageSinkType.LocalWormFile };

        /// <summary>
        /// Gets or sets the threat defense operating mode applied during the ingestion of this event.
        /// </summary>
        public ThreatDefenseMode DefenseModeApplied { get; set; } = ThreatDefenseMode.AuditOnly;

        /// <summary>
        /// Gets or sets the compliance standards satisfied by this log record.
        /// </summary>
        public ComplianceStandard ComplianceFlags { get; set; } =
            ComplianceStandard.ThaiComputerCrimeAct2560Sec26 |
            ComplianceStandard.ThaiPdpa |
            ComplianceStandard.Gdpr |
            ComplianceStandard.Iso27001;
    }
}
