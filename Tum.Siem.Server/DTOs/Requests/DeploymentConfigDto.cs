// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Tum.Siem.Server.DTOs.Requests;

public enum ArchitectureTier
{
    SingleNodeLab = 1,
    EnterpriseCluster = 2,
    NationalFlashCrowd = 3
}

public sealed class DeploymentConfigDto
{
    public ArchitectureTier Tier { get; set; } = ArchitectureTier.EnterpriseCluster;
    public string DomainName { get; set; } = "siem.tum-enterprise.internal";
    public int HttpPort { get; set; } = 5200;
    public int SyslogUdpPort { get; set; } = 514;
    public int SyslogTcpPort { get; set; } = 514;
    public int WormRetentionDays { get; set; } = 90;
    public string ClickHousePassword { get; set; } = "tum_sovereign_2026";
    public string ClickHouseMemoryLimit { get; set; } = "16Gi";
    public bool EnableRedpandaQueue { get; set; } = true;
    public bool EnableSmartSamplingSurge { get; set; } = true;
    public int ReplicaCount { get; set; } = 2;
    public int StorageSizeGb { get; set; } = 200;
    public string NtpServerHost { get; set; } = "time.navy.mi.th";
}
