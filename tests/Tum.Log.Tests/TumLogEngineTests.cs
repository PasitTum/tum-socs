// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using System.IO;
using System.Threading.Tasks;
using Tum.Trust.Security.Core.Models.Logging;
using Tum.Trust.Security.Infrastructure.Logging;
using Xunit;

namespace Tum.Trust.Security.Tests
{
    public class TumLogEngineTests
    {
        private readonly TumPiiSanitizer _sanitizer = new();
        private readonly TumThreatDetector _threatDetector = new();

        [Fact]
        public void ThaiNationalId_ValidChecksum_PassesVerificationAndRedacted()
        {
            // Valid Thai ID constructed with Modulo-11 formula: 1-1007-01234-56-1
            string validThaiId = "1100701234561";
            Assert.True(_sanitizer.IsValidThaiNationalId(validThaiId));

            string payload = $"User verified with citizen ID {validThaiId} at kiosk";
            var (sanitized, detections) = _sanitizer.SanitizeText(payload);

            Assert.Single(detections);
            Assert.Equal(PiiType.ThaiNationalId, detections[0].Type);
            Assert.Equal("1-XXXX-XXXXX-XX-1", detections[0].MaskedSnippet);
            Assert.Contains("1-XXXX-XXXXX-XX-1", sanitized);
            Assert.DoesNotContain(validThaiId, sanitized);
        }

        [Fact]
        public void ThaiNationalId_InvalidChecksum_IgnoredFromRedaction()
        {
            string invalidId = "1234567890123";
            Assert.False(_sanitizer.IsValidThaiNationalId(invalidId));

            string payload = $"Serial number is {invalidId}";
            var (sanitized, detections) = _sanitizer.SanitizeText(payload);

            Assert.Empty(detections);
            Assert.Equal(payload, sanitized);
        }

        [Fact]
        public void CreditCard_LuhnValid_RedactedProperly()
        {
            // Standard Luhn-valid test PAN: 4111 1111 1111 1111
            string card = "4111-1111-1111-1111";
            Assert.True(_sanitizer.IsValidCreditCard(card));

            string payload = $"Payment processed for card {card}";
            var (sanitized, detections) = _sanitizer.SanitizeText(payload);

            Assert.Single(detections);
            Assert.Equal(PiiType.CreditCardNumber, detections[0].Type);
            Assert.Equal("4111-XXXX-XXXX-1111", detections[0].MaskedSnippet);
            Assert.Contains("4111-XXXX-XXXX-1111", sanitized);
            Assert.DoesNotContain("4111-1111-1111-1111", sanitized);
        }

        [Fact]
        public void BearerJwtAndSecrets_RedactedFromLog()
        {
            string jwt = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature";
            string payload = $"{{\"user\": \"admin\", \"token\": \"{jwt}\", \"password\": \"SuperSecret99$\"}}";

            var (sanitized, detections) = _sanitizer.SanitizeText(payload);

            Assert.True(detections.Count >= 2);
            Assert.DoesNotContain("SuperSecret99$", sanitized);
            Assert.DoesNotContain("eyJhbGciOiJIUzI1Ni", sanitized);
            Assert.Contains("[REDACTED_SECRET]", sanitized);
        }

        [Theory]
        [InlineData("SELECT * FROM users WHERE id = 1 UNION SELECT username, password FROM accounts", ThreatType.SqlInjection)]
        [InlineData("/api/search?q=' OR 1=1 --", ThreatType.SqlInjection)]
        [InlineData("<script>alert('pwned')</script>", ThreatType.CrossSiteScripting)]
        [InlineData("javascript:evilCode()", ThreatType.CrossSiteScripting)]
        [InlineData("../../etc/passwd", ThreatType.PathTraversal)]
        [InlineData("..\\windows\\win.ini", ThreatType.PathTraversal)]
        [InlineData("; cat /etc/shadow", ThreatType.CommandInjection)]
        public void ThreatDetector_IdentifiesMaliciousVectors(string maliciousInput, ThreatType expectedThreat)
        {
            var alerts = _threatDetector.InspectPayload(maliciousInput);

            Assert.NotEmpty(alerts);
            Assert.Contains(alerts, a => a.ThreatType == expectedThreat);
        }

        [Fact]
        public async Task TamperProofLogChain_AppendsEntries_VerifiesIntegrity()
        {
            string tempDir = Path.Combine(Path.GetTempPath(), "tumlog_test_" + Guid.NewGuid().ToString("N"));
            var options = new TumLogOptions { StorageDirectory = tempDir, WormRetentionDays = 90 };
            var chain = new TamperProofLogChain(options);

            try
            {
                var entry1 = new TumLogEntry
                {
                    EventName = "User.Login",
                    Category = LogCategory.AuditTrail,
                    PayloadSanitized = "User login successful",
                    ClientIp = "192.168.1.10"
                };

                var entry2 = new TumLogEntry
                {
                    EventName = "Payment.Checkout",
                    Category = LogCategory.BusinessTransaction,
                    PayloadSanitized = "Amount 5000 THB",
                    ClientIp = "192.168.1.10"
                };

                var receipt1 = await chain.AppendEntryAsync(entry1);
                var receipt2 = await chain.AppendEntryAsync(entry2);

                Assert.Equal("0000000000000000000000000000000000000000000000000000000000000000", receipt1.PreviousEntryHashSha256);
                Assert.Equal(receipt1.EntryHashSha256, receipt2.PreviousEntryHashSha256);
                Assert.True(receipt1.IsChainIntact);
                Assert.True(receipt2.IsChainIntact);

                bool intact = await chain.VerifyChainIntegrityAsync();
                Assert.True(intact);

                var recent = await chain.GetRecentEntriesAsync(10);
                Assert.Equal(2, recent.Count);
            }
            finally
            {
                if (Directory.Exists(tempDir))
                {
                    try { Directory.Delete(tempDir, true); } catch { }
                }
            }
        }

        [Fact]
        public async Task TumLogEngine_EndToEndPipeline_RedactsPiiAndDetectsThreat()
        {
            string tempDir = Path.Combine(Path.GetTempPath(), "tumlog_e2e_" + Guid.NewGuid().ToString("N"));
            var options = new TumLogOptions { StorageDirectory = tempDir };
            var engine = new TumLogEngine(options: options);

            try
            {
                string rawPayload = "Attacker submitted citizen ID 1100701234561 with query: ' OR 1=1 --";
                var logged = await engine.LogEventAsync(
                    "User.Search",
                    LogCategory.AuditTrail,
                    rawPayload,
                    userId: "usr_999",
                    clientIp: "203.0.113.42");

                Assert.NotNull(logged);
                Assert.Equal(LogCategory.SecurityThreat, logged.Category); // Escalated due to threat
                Assert.Equal("Critical", logged.Severity);
                Assert.Contains("1-XXXX-XXXXX-XX-1", logged.PayloadSanitized);
                Assert.NotEmpty(logged.SecurityThreats);
                Assert.False(string.IsNullOrEmpty(logged.TamperProofHash));
                Assert.False(string.IsNullOrEmpty(logged.MerkleRoot));

                bool chainValid = await engine.VerifyIntegrityAsync();
                Assert.True(chainValid);
            }
            finally
            {
                if (Directory.Exists(tempDir))
                {
                    try { Directory.Delete(tempDir, true); } catch { }
                }
            }
        }

        [Fact]
        public void TumAuditAttribute_ExposesConfiguredMetadata()
        {
            var attr = new TumAuditAttribute("Order.PaymentReceived", LogCategory.BusinessTransaction)
            {
                Severity = "High",
                CaptureParameters = true
            };

            Assert.Equal("Order.PaymentReceived", attr.EventName);
            Assert.Equal(LogCategory.BusinessTransaction, attr.Category);
            Assert.Equal("High", attr.Severity);
            Assert.True(attr.CaptureParameters);
        }
    }
}
