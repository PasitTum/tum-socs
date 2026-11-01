// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Tum.Siem.Server.DTOs.Requests;

/// <summary>
/// Query parameters for event log exploration.
/// </summary>
public sealed class QueryLogsRequest
{
    /// <summary>
    /// Lucene or SQL-style search term (e.g. 'Status=404', 'ClientIp=192.168.1.*', or wildcard '*').
    /// </summary>
    public string Query { get; set; } = "*";

    /// <summary>
    /// Maximum number of records to return.
    /// </summary>
    public int Limit { get; set; } = 100;

    /// <summary>
    /// Offset for pagination.
    /// </summary>
    public int Offset { get; set; } = 0;
}
