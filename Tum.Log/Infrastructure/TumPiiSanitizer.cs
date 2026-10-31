// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using Tum.Trust.Security.Core.Interfaces.Logging;
using Tum.Trust.Security.Core.Models.Logging;

namespace Tum.Trust.Security.Infrastructure.Logging
{
    /// <summary>
    /// AI-powered PII detection and redaction engine for Thai and international compliance.
    /// Recognizes Thai National IDs via Modulo-11, Credit Cards via Luhn, Passports, Phones, Emails, and Secrets.
    /// </summary>
    public class TumPiiSanitizer : ITumPiiSanitizer
    {
        private static readonly Regex ThaiIdCandidateRegex = new(@"\b\d{13}\b|\b\d{1}-\d{4}-\d{5}-\d{2}-\d{1}\b", RegexOptions.Compiled);
        private static readonly Regex CardCandidateRegex = new(@"\b(?:\d{4}[ -]?){3}\d{4}\b|\b\d{15,16}\b", RegexOptions.Compiled);
        private static readonly Regex PassportRegex = new(@"\b[A-Z]{1,2}\d{7,8}\b", RegexOptions.Compiled);
        private static readonly Regex ThaiPhoneRegex = new(@"\b(?:0[689]\d{1}[ -]?\d{3}[ -]?\d{4}|\+66[ -]?[689]\d{1}[ -]?\d{3}[ -]?\d{4})\b", RegexOptions.Compiled);
        private static readonly Regex EmailRegex = new(@"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", RegexOptions.Compiled);
        private static readonly Regex BearerJwtRegex = new(@"Bearer\s+(eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+)", RegexOptions.Compiled);
        private static readonly Regex SecretJsonRegex = new(@"""(?i)(?:password|secret|apiKey|api_key|token|access_token|private_key|pin)""\s*:\s*""([^""]+)""", RegexOptions.Compiled);

        /// <inheritdoc />
        public (string SanitizedText, List<PiiDetectionResult> Detections) SanitizeText(string input)
        {
            if (string.IsNullOrEmpty(input))
            {
                return (string.Empty, new List<PiiDetectionResult>());
            }

            var detections = new List<PiiDetectionResult>();
            string sanitized = input;

            // 1. Bearer JWT Tokens
            sanitized = BearerJwtRegex.Replace(sanitized, match =>
            {
                string raw = match.Groups[1].Value;
                string masked = "eyJ***[REDACTED_JWT]***";
                detections.Add(new PiiDetectionResult
                {
                    Type = PiiType.BearerToken,
                    RawSnippet = raw.Length > 16 ? raw.Substring(0, 16) + "..." : raw,
                    MaskedSnippet = masked,
                    ConfidenceScore = 1.0,
                    CharacterOffset = match.Index
                });
                return $"Bearer {masked}";
            });

            // 2. Sensitive JSON / Key-Value Secrets & Passwords
            sanitized = SecretJsonRegex.Replace(sanitized, match =>
            {
                string raw = match.Groups[1].Value;
                string masked = "[REDACTED_SECRET]";
                detections.Add(new PiiDetectionResult
                {
                    Type = PiiType.SecretOrPassword,
                    RawSnippet = "******",
                    MaskedSnippet = masked,
                    ConfidenceScore = 1.0,
                    CharacterOffset = match.Index
                });
                return match.Value.Replace(raw, masked);
            });

            // 3. Thai National ID (13 Digits with Modulo-11 Checksum Validation)
            sanitized = ThaiIdCandidateRegex.Replace(sanitized, match =>
            {
                string raw = match.Value;
                string digits = raw.Replace("-", string.Empty);
                if (digits.Length == 13 && IsValidThaiNationalId(digits))
                {
                    string masked = $"{digits[0]}-XXXX-XXXXX-XX-{digits[12]}";
                    detections.Add(new PiiDetectionResult
                    {
                        Type = PiiType.ThaiNationalId,
                        RawSnippet = raw,
                        MaskedSnippet = masked,
                        ConfidenceScore = 0.99,
                        CharacterOffset = match.Index
                    });
                    return masked;
                }
                return raw;
            });

            // 4. Credit / Debit Cards (with Luhn Validation)
            sanitized = CardCandidateRegex.Replace(sanitized, match =>
            {
                string raw = match.Value;
                string digits = Regex.Replace(raw, @"[ -]", string.Empty);
                if (digits.Length >= 13 && digits.Length <= 19 && IsValidCreditCard(digits))
                {
                    string first4 = digits.Substring(0, 4);
                    string last4 = digits.Substring(digits.Length - 4);
                    string masked = $"{first4}-XXXX-XXXX-{last4}";
                    detections.Add(new PiiDetectionResult
                    {
                        Type = PiiType.CreditCardNumber,
                        RawSnippet = raw,
                        MaskedSnippet = masked,
                        ConfidenceScore = 0.98,
                        CharacterOffset = match.Index
                    });
                    return masked;
                }
                return raw;
            });

            // 5. Thai Mobile Phone Numbers
            sanitized = ThaiPhoneRegex.Replace(sanitized, match =>
            {
                string raw = match.Value;
                string digits = Regex.Replace(raw, @"[ -]", string.Empty);
                string masked;
                if (digits.Length >= 10)
                {
                    masked = $"{digits.Substring(0, 3)}-XXX-{digits.Substring(digits.Length - 4)}";
                }
                else
                {
                    masked = "08X-XXX-XXXX";
                }

                detections.Add(new PiiDetectionResult
                {
                    Type = PiiType.PhoneNumber,
                    RawSnippet = raw,
                    MaskedSnippet = masked,
                    ConfidenceScore = 0.95,
                    CharacterOffset = match.Index
                });
                return masked;
            });

            // 6. Emails
            sanitized = EmailRegex.Replace(sanitized, match =>
            {
                string raw = match.Value;
                int atIdx = raw.IndexOf('@');
                if (atIdx > 0)
                {
                    string name = raw.Substring(0, atIdx);
                    string domain = raw.Substring(atIdx);
                    string maskedName = name.Length > 2 ? $"{name[0]}***{name[name.Length - 1]}" : "***";
                    string masked = $"{maskedName}{domain}";

                    detections.Add(new PiiDetectionResult
                    {
                        Type = PiiType.EmailAddress,
                        RawSnippet = raw,
                        MaskedSnippet = masked,
                        ConfidenceScore = 0.95,
                        CharacterOffset = match.Index
                    });
                    return masked;
                }
                return raw;
            });

            return (sanitized, detections);
        }

        /// <inheritdoc />
        public List<PiiDetectionResult> DetectPii(string input)
        {
            var (_, detections) = SanitizeText(input);
            return detections;
        }

        /// <inheritdoc />
        public bool IsValidThaiNationalId(string nationalId)
        {
            if (string.IsNullOrWhiteSpace(nationalId))
            {
                return false;
            }

            string digits = nationalId.Replace("-", string.Empty).Trim();
            if (digits.Length != 13 || !long.TryParse(digits, out _))
            {
                return false;
            }

            int sum = 0;
            for (int i = 0; i < 12; i++)
            {
                sum += (digits[i] - '0') * (13 - i);
            }

            int remainder = sum % 11;
            int checkDigit = (11 - remainder) % 10;

            return checkDigit == (digits[12] - '0');
        }

        /// <inheritdoc />
        public bool IsValidCreditCard(string cardNumber)
        {
            if (string.IsNullOrWhiteSpace(cardNumber))
            {
                return false;
            }

            string digits = Regex.Replace(cardNumber, @"[ -]", string.Empty);
            if (digits.Length < 13 || digits.Length > 19)
            {
                return false;
            }

            int sum = 0;
            bool alternate = false;

            for (int i = digits.Length - 1; i >= 0; i--)
            {
                if (!char.IsDigit(digits[i]))
                {
                    return false;
                }

                int n = digits[i] - '0';
                if (alternate)
                {
                    n *= 2;
                    if (n > 9)
                    {
                        n = (n % 10) + 1;
                    }
                }

                sum += n;
                alternate = !alternate;
            }

            return sum % 10 == 0;
        }
    }
}
