// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Tum.Siem.Server.DTOs.Requests;

public sealed record LoadDatasetRequest
{
    /// <summary>
    /// Identifier of the dataset to load ('all', 'ssh_bruteforce', 'web_cve_exploits', 'pdpa_ecommerce', 'ransomware_canary').
    /// </summary>
    public string DatasetId { get; init; } = "all";

    /// <summary>
    /// Max records to ingest.
    /// </summary>
    public int Limit { get; init; } = 50;
}
