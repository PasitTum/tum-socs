// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Collections.Generic;
using Tum.Trust.Security.Core.Models.Logging;
using Tum.Trust.Security.Core.Models.Query;
using Tum.Trust.Security.Infrastructure.Query;
using Xunit;

namespace Tum.Trust.Security.Tests
{
    public class EventQueryEngineTests
    {
        private readonly EventQueryEngine _engine = new();

        private readonly List<TumLogEntry> _sampleEntries = new()
        {
            new TumLogEntry
            {
                LogId = "log-001",
                EventName = "AUTH.LOGIN",
                Category = LogCategory.AuditTrail,
                Severity = "Information",
                ClientIp = "192.168.1.50",
                UserId = "alice",
                PayloadSanitized = "User alice logged in successfully from desktop"
            },
            new TumLogEntry
            {
                LogId = "log-002",
                EventName = "HTTP.REQUEST",
                Category = LogCategory.SecurityThreat,
                Severity = "Critical",
                ClientIp = "203.0.113.195",
                RequestPath = "/api/v1/users",
                HttpMethod = "POST",
                StatusCode = 500,
                PayloadSanitized = "POST /api/v1/users id=1 UNION SELECT password FROM users--"
            },
            new TumLogEntry
            {
                LogId = "log-003",
                EventName = "FILE.ACCESS",
                Category = LogCategory.PiiAccess,
                Severity = "Warning",
                ClientIp = "10.0.0.12",
                UserId = "bob",
                RequestPath = "/export/customer_records.csv",
                PayloadSanitized = "Exported 500 Thai Citizen KYC records"
            }
        };

        [Fact]
        public void ExecuteQuery_MatchesFieldExact_AndTranslatesToSql()
        {
            var req = new EventQueryRequest
            {
                Query = "category:SecurityThreat AND severity:Critical"
            };

            var res = _engine.ExecuteQuery(_sampleEntries, req);

            Assert.Equal(1, res.TotalMatched);
            Assert.Single(res.Items);
            Assert.Equal("log-002", res.Items[0].LogId);
            Assert.Contains("category = 'SecurityThreat'", res.TranslatedSqlWhere);
            Assert.Contains("severity = 'Critical'", res.TranslatedSqlWhere);
        }

        [Fact]
        public void ExecuteQuery_SupportsWildcardAndFreeTextSearch()
        {
            var req = new EventQueryRequest
            {
                Query = "\"UNION SELECT\""
            };

            var res = _engine.ExecuteQuery(_sampleEntries, req);

            Assert.Equal(1, res.TotalMatched);
            Assert.Equal("log-002", res.Items[0].LogId);
            Assert.Contains("payload_sanitized LIKE '%UNION SELECT%'", res.TranslatedSqlWhere);
        }

        [Fact]
        public void ExecuteQuery_SupportsWildcardOnFieldNames()
        {
            var req = new EventQueryRequest
            {
                Query = "event:AUTH.*"
            };

            var res = _engine.ExecuteQuery(_sampleEntries, req);

            Assert.Equal(1, res.TotalMatched);
            Assert.Equal("log-001", res.Items[0].LogId);
        }

        [Fact]
        public void ExecuteQuery_SupportsNotOperator()
        {
            var req = new EventQueryRequest
            {
                Query = "category:SecurityThreat NOT user:bob"
            };

            var res = _engine.ExecuteQuery(_sampleEntries, req);

            Assert.Equal(1, res.TotalMatched);
            Assert.Equal("log-002", res.Items[0].LogId);
        }

        [Fact]
        public void ExecuteQuery_SupportsStatusCodeNumericFilter()
        {
            var req = new EventQueryRequest
            {
                Query = "status:500"
            };

            var res = _engine.ExecuteQuery(_sampleEntries, req);

            Assert.Equal(1, res.TotalMatched);
            Assert.Equal(500, res.Items[0].StatusCode);
            Assert.Contains("status_code = 500", res.TranslatedSqlWhere);
        }
    }
}
