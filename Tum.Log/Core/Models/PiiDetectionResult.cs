// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Tum.Trust.Security.Core.Models.Logging
{
    /// <summary>
    /// Represents a detected Personal Identifiable Information (PII) entity within a log payload.
    /// </summary>
    public class PiiDetectionResult
    {
        /// <summary>
        /// Gets or sets the classification of the detected PII.
        /// </summary>
        public PiiType Type { get; set; }

        /// <summary>
        /// Gets or sets the original raw snippet identified.
        /// </summary>
        public string RawSnippet { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the safely masked replacement snippet.
        /// </summary>
        public string MaskedSnippet { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the confidence score of the detection (0.0 to 1.0).
        /// </summary>
        public double ConfidenceScore { get; set; } = 1.0;

        /// <summary>
        /// Gets or sets the character index offset where the PII was located in the original payload.
        /// </summary>
        public int CharacterOffset { get; set; }
    }
}
