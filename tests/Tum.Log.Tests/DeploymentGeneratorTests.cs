// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.IO.Compression;
using Microsoft.AspNetCore.Mvc;
using Tum.Siem.Server.Controllers;
using Tum.Siem.Server.DTOs.Requests;
using Tum.Siem.Server.DTOs.Responses;
using Tum.Siem.Server.Services;
using Xunit;

namespace Tum.Trust.Security.Tests;

public class DeploymentGeneratorTests
{
    private readonly DeploymentGeneratorService _service = new();

    [Fact]
    public void GenerateBundle_SingleNodeLab_Should_Generate_Valid_Files()
    {
        var config = new DeploymentConfigDto
        {
            Tier = ArchitectureTier.SingleNodeLab,
            DomainName = "siem.lab.local",
            HttpPort = 5200,
            WormRetentionDays = 90
        };

        var bundle = _service.GenerateBundle(config);

        Assert.Equal(ArchitectureTier.SingleNodeLab, bundle.Tier);
        Assert.NotEmpty(bundle.Files);
        Assert.Contains(bundle.Files, f => f.Path == "docker-compose.yml" && f.Content.Contains("clickhouse/clickhouse-server"));
        Assert.Contains(bundle.Files, f => f.Path == ".env" && f.Content.Contains("WORM_RETENTION_DAYS=90"));
        Assert.Contains(bundle.Files, f => f.Path == "init-clickhouse.sql");
        Assert.Contains(bundle.Files, f => f.Path == "start.sh");
        Assert.NotNull(bundle.Hardware);
        Assert.Equal("5,000 EPS", bundle.Hardware.MaxSustainedEps);
    }

    [Fact]
    public void GenerateBundle_EnterpriseCluster_Should_Include_Redpanda_And_Sysctl()
    {
        var config = new DeploymentConfigDto
        {
            Tier = ArchitectureTier.EnterpriseCluster,
            DomainName = "siem.enterprise.corp",
            EnableRedpandaQueue = true
        };

        var bundle = _service.GenerateBundle(config);

        Assert.Equal(ArchitectureTier.EnterpriseCluster, bundle.Tier);
        Assert.Contains(bundle.Files, f => f.Path == "docker-compose.enterprise.yml" && f.Content.Contains("redpanda"));
        Assert.Contains(bundle.Files, f => f.Path == "sysctl-tuning.conf" && f.Content.Contains("somaxconn"));
        Assert.Equal("50,000 EPS", bundle.Hardware.MaxSustainedEps);
        Assert.Equal("25,000 Concurrent Users", bundle.Hardware.PeakConcurrencyUsers);
    }

    [Fact]
    public void GenerateBundle_NationalFlashCrowd_Should_Include_Helm_And_KEDA_Autoscaler()
    {
        var config = new DeploymentConfigDto
        {
            Tier = ArchitectureTier.NationalFlashCrowd,
            DomainName = "siem.ocsc.go.th",
            ReplicaCount = 6,
            EnableSmartSamplingSurge = true
        };

        var bundle = _service.GenerateBundle(config);

        Assert.Equal(ArchitectureTier.NationalFlashCrowd, bundle.Tier);
        Assert.Contains(bundle.Files, f => f.Path == "helm-values.yaml" && f.Content.Contains("siem.ocsc.go.th"));
        Assert.Contains(bundle.Files, f => f.Path == "keda-autoscaler.yaml" && f.Content.Contains("ScaledObject"));
        Assert.Contains(bundle.Files, f => f.Path == "surge-governor.json" && f.Content.Contains("guaranteedForensicRetention"));
        Assert.Contains(bundle.Files, f => f.Path == "deploy-k8s.sh");
        Assert.Equal("> 150,000 EPS", bundle.Hardware.MaxSustainedEps);
    }

    [Fact]
    public async Task GenerateZipArchiveAsync_Should_Create_Valid_Zip_With_All_Files()
    {
        var config = new DeploymentConfigDto
        {
            Tier = ArchitectureTier.EnterpriseCluster
        };

        byte[] zipBytes = await _service.GenerateZipArchiveAsync(config);
        Assert.NotNull(zipBytes);
        Assert.True(zipBytes.Length > 0);

        using var memoryStream = new MemoryStream(zipBytes);
        using var archive = new ZipArchive(memoryStream, ZipArchiveMode.Read);

        var bundle = _service.GenerateBundle(config);
        Assert.Equal(bundle.Files.Count, archive.Entries.Count);

        foreach (var expectedFile in bundle.Files)
        {
            var entry = archive.GetEntry(expectedFile.Path);
            Assert.NotNull(entry);
        }
    }

    [Fact]
    public void DeploymentController_Should_Return_Bundle_And_Presets()
    {
        var controller = new DeploymentController(_service);

        var result = controller.Generate(new DeploymentConfigDto { Tier = ArchitectureTier.SingleNodeLab });
        var okResult = Assert.IsType<OkObjectResult>(result);
        var bundle = Assert.IsType<DeploymentBundleResponse>(okResult.Value);
        Assert.Equal(ArchitectureTier.SingleNodeLab, bundle.Tier);

        var presetsResult = controller.GetPresets();
        var presetsOk = Assert.IsType<OkObjectResult>(presetsResult);
        Assert.NotNull(presetsOk.Value);
    }
}
