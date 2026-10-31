// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Tum.Trust.Security.Core.Models.Logging;
using Tum.Trust.Security.Infrastructure.Logging;
using Xunit;

namespace Tum.Trust.Security.Tests
{
    public class TumLogEnterpriseTests
    {
        private readonly TumPiiSanitizer _sanitizer = new();
        private readonly OutboundLeakDetector _outboundLeakDetector = new();
        private readonly EndpointRegistry _endpointRegistry = new();

        [Fact]
        public void OutboundLeakDetector_CatchesPiiAndSuppressesDbErrors()
        {
            string leakingResponse = @"{
                ""status"": ""error"",
                ""citizenId"": ""1100701234561"",
                ""debug"": ""Microsoft OLE DB Provider for SQL Server: syntax error at or near 'SELECT'""
            }";

            var (sanitized, leaks) = _outboundLeakDetector.InspectAndSanitizeOutbound(leakingResponse, 500);

            Assert.NotEmpty(leaks);
            Assert.Contains(leaks, l => l.LeakType == OutboundLeakType.PiiLeakagePrevented);
            Assert.Contains(leaks, l => l.LeakType == OutboundLeakType.DatabaseErrorSuppressed);

            Assert.DoesNotContain("1100701234561", sanitized);
            Assert.Contains("1-XXXX-XXXXX-XX-1", sanitized);
            Assert.DoesNotContain("Microsoft OLE DB Provider", sanitized);
            Assert.Contains("[SEC_SUPPRESSED:", sanitized);
        }

        [Fact]
        public void OutboundLeakDetector_BlocksPrivateKeyExfiltration()
        {
            string rawKeyResponse = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0Y...==\n-----END RSA PRIVATE KEY-----";

            var (sanitized, leaks) = _outboundLeakDetector.InspectAndSanitizeOutbound(rawKeyResponse, 200);

            Assert.Single(leaks);
            Assert.Equal(OutboundLeakType.SecretTokenExposed, leaks[0].LeakType);
            Assert.Equal("Critical", leaks[0].Severity);
            Assert.Contains("[SEC_BLOCKED:", sanitized);
            Assert.DoesNotContain("BEGIN RSA PRIVATE KEY", sanitized);
        }

        [Fact]
        public void EndpointRegistry_AccuratelyTracksPiiRoutesAndRiskLevel()
        {
            _endpointRegistry.RecordEndpointAccess(
                "/api/v1/kyc/verify",
                "POST",
                hasInboundPii: true,
                hasOutboundPii: true,
                piiTypes: new[] { PiiType.ThaiNationalId, PiiType.PassportNumber },
                hasThreat: false);

            _endpointRegistry.RecordEndpointAccess(
                "/api/v1/public/ping",
                "GET",
                hasInboundPii: false,
                hasOutboundPii: false,
                piiTypes: Array.Empty<PiiType>(),
                hasThreat: false);

            var endpoints = _endpointRegistry.GetAllEndpoints();
            Assert.Equal(2, endpoints.Count);

            var kycProfile = _endpointRegistry.GetProfile("/api/v1/kyc/verify", "POST");
            Assert.NotNull(kycProfile);
            Assert.True(kycProfile.InboundPiiDetected);
            Assert.True(kycProfile.OutboundPiiDetected);
            Assert.Equal(2, kycProfile.ObservedPiiTypes.Count);
            Assert.Equal("Critical", kycProfile.RiskLevel);

            var pingProfile = _endpointRegistry.GetProfile("/api/v1/public/ping", "GET");
            Assert.NotNull(pingProfile);
            Assert.False(pingProfile.InboundPiiDetected);
            Assert.Equal("Low", pingProfile.RiskLevel);
        }

        [Theory]
        [InlineData("user login", 32, "USER_LOGIN")]
        [InlineData("payment.checkout.processed-success", 20, "PAYMENT.CHECKOUT.PRO")]
        [InlineData(null, 32, "GENERIC.EVENT")]
        [InlineData("", 32, "GENERIC.EVENT")]
        public void StandardEventAction_NormalizesAndEnforcesLength(string? raw, int maxLen, string expected)
        {
            string normalized = StandardEventAction.Normalize(raw, maxLen);
            Assert.Equal(expected, normalized);
            Assert.True(normalized.Length <= maxLen);
        }

        [Fact]
        public async Task MultiDestinationSink_DispatchesToLocalWormAndSyslog()
        {
            string tempDir = Path.Combine(Path.GetTempPath(), "tumlog_sink_test_" + Guid.NewGuid().ToString("N"));
            var options = new TumLogOptions
            {
                StorageDirectory = tempDir,
                Destinations =
                {
                    new LogDestinationConfig { SinkType = StorageSinkType.LocalWormFile, IsEnabled = true },
                    new LogDestinationConfig { SinkType = StorageSinkType.SyslogRfc5424, IsEnabled = true, EndpointUri = "syslog://siem.internal:514" }
                }
            };

            var engine = new TumLogEngine(options: options);

            try
            {
                var entry = new TumLogEntry
                {
                    EventName = "AUTH.LOGIN",
                    Category = LogCategory.AuditTrail,
                    PayloadSanitized = "User login via ThaID successful",
                    ClientIp = "192.168.1.50",
                    RequestPath = "/api/v1/auth/login",
                    HttpMethod = "POST"
                };

                var result = await engine.LogAsync(entry);

                Assert.NotNull(result);
                Assert.Contains(StorageSinkType.LocalWormFile, result.DispatchedSinks);
                Assert.Contains(StorageSinkType.SyslogRfc5424, result.DispatchedSinks);

                // Verify endpoint cataloged
                var profile = engine.EndpointRegistry.GetProfile("/api/v1/auth/login", "POST");
                Assert.NotNull(profile);
                Assert.Equal(1, profile.TotalInvocationCount);
            }
            finally
            {
                if (Directory.Exists(tempDir))
                {
                    try { Directory.Delete(tempDir, true); } catch { }
                }
            }
        }
    }
}
