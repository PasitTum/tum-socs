// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Collections.Generic;

namespace Tum.Trust.Security.Core.Models.Risk
{
    /// <summary>
    /// Configuration options for the TUM-OpenSIEM Dynamic Risk Pipeline.
    /// </summary>
    public class DynamicRiskOptions
    {
        /// <summary>
        /// Base risk score for Critical Sigma rule match. Defaults to 50.0.
        /// </summary>
        public double SigmaCriticalScore { get; set; } = 50.0;

        /// <summary>
        /// Base risk score for High Sigma rule match. Defaults to 35.0.
        /// </summary>
        public double SigmaHighScore { get; set; } = 35.0;

        /// <summary>
        /// Base risk score for Medium Sigma rule match. Defaults to 20.0.
        /// </summary>
        public double SigmaMediumScore { get; set; } = 20.0;

        /// <summary>
        /// Base risk score for Low Sigma rule match. Defaults to 10.0.
        /// </summary>
        public double SigmaLowScore { get; set; } = 10.0;

        /// <summary>
        /// Risk points added per detected PII entity. Defaults to 5.0.
        /// </summary>
        public double PiiExposureUnitScore { get; set; } = 5.0;

        /// <summary>
        /// Maximum risk cap for PII exposures. Defaults to 25.0.
        /// </summary>
        public double MaxPiiRiskScore { get; set; } = 25.0;

        /// <summary>
        /// Risk points added for inbound OWASP threat detections. Defaults to 30.0.
        /// </summary>
        public double InboundThreatScore { get; set; } = 30.0;

        /// <summary>
        /// Risk points added for outbound sensitive data leak detections. Defaults to 35.0.
        /// </summary>
        public double OutboundLeakScore { get; set; } = 35.0;

        /// <summary>
        /// Risk points added for high-impact MITRE ATT&amp;CK techniques (e.g. execution, exfiltration, privilege-escalation).
        /// </summary>
        public double HighImpactMitreBonus { get; set; } = 15.0;

        /// <summary>
        /// Minimum risk score threshold required to trigger automated alerts. Defaults to 70.0 (High/Critical).
        /// </summary>
        public double AlertThreshold { get; set; } = 70.0;

        /// <summary>
        /// Multipliers for asset environments. E.g. 'Production' => 1.2, 'Staging' => 1.0, 'Development' => 0.8.
        /// </summary>
        public Dictionary<string, double> EnvironmentMultipliers { get; set; } =
            new Dictionary<string, double>(System.StringComparer.OrdinalIgnoreCase)
            {
                { "Production", 1.2 },
                { "Staging", 1.0 },
                { "Development", 0.7 }
            };
    }
}
