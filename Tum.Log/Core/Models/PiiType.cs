// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Tum.Trust.Security.Core.Models.Logging
{
    /// <summary>
    /// Types of Personal Identifiable Information (PII) recognized and redacted by TUMLog AI.
    /// </summary>
    public enum PiiType
    {
        /// <summary>
        /// Thai National Identification Number (13 digits, validated by Modulo-11 checksum).
        /// </summary>
        ThaiNationalId = 1,

        /// <summary>
        /// International or Thai Passport Number.
        /// </summary>
        PassportNumber = 2,

        /// <summary>
        /// Credit/Debit Card Number (Primary Account Number validated via Luhn algorithm).
        /// </summary>
        CreditCardNumber = 3,

        /// <summary>
        /// Thai Mobile Phone Number (08x, 09x, 06x) or international E.164 phone numbers.
        /// </summary>
        PhoneNumber = 4,

        /// <summary>
        /// Email address.
        /// </summary>
        EmailAddress = 5,

        /// <summary>
        /// JSON Web Token (Bearer JWT tokens: eyJ...).
        /// </summary>
        BearerToken = 6,

        /// <summary>
        /// API Keys, Secret Tokens, Private Keys, or Passwords.
        /// </summary>
        SecretOrPassword = 7
    }
}
