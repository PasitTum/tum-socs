// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Collections.Generic;
using Tum.Trust.Security.Core.Models.Logging;

namespace Tum.Trust.Security.Core.Interfaces.Logging
{
    /// <summary>
    /// AI-driven Personal Identifiable Information (PII) detection and redaction engine conforming to Thai PDPA and GDPR.
    /// </summary>
    public interface ITumPiiSanitizer
    {
        /// <summary>
        /// Scans an input string, detects sensitive PII entities (Thai Citizen IDs, Passports, Credit Cards, Phones, JWTs),
        /// and returns both the sanitized string and a list of detected redactions.
        /// </summary>
        /// <param name="input">The raw text or JSON payload.</param>
        /// <returns>A tuple of sanitized text and the detected PII items.</returns>
        (string SanitizedText, List<PiiDetectionResult> Detections) SanitizeText(string input);

        /// <summary>
        /// Scans an input string and returns all detected PII entities without modifying the original text.
        /// </summary>
        /// <param name="input">The text to analyze.</param>
        /// <returns>List of detected PII entities.</returns>
        List<PiiDetectionResult> DetectPii(string input);

        /// <summary>
        /// Validates whether a 13-digit number satisfies the official Thai National Identification Modulo-11 checksum formula.
        /// </summary>
        /// <param name="nationalId">The 13-digit string.</param>
        /// <returns><c>true</c> if mathematically valid; otherwise <c>false</c>.</returns>
        bool IsValidThaiNationalId(string nationalId);

        /// <summary>
        /// Validates whether a credit or debit card primary account number (PAN) satisfies the Luhn algorithm.
        /// </summary>
        /// <param name="cardNumber">The numeric card string.</param>
        /// <returns><c>true</c> if valid under Luhn mod 10; otherwise <c>false</c>.</returns>
        bool IsValidCreditCard(string cardNumber);
    }
}
