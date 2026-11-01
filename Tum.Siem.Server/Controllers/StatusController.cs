// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Tum.Siem.Server.Configuration;
using Tum.Siem.Server.DTOs.Responses;
using Tum.Trust.Security.Core.Interfaces.Logging;
using Tum.Trust.Security.Core.Models.Logging;

namespace Tum.Siem.Server.Controllers;

[ApiController]
[Route("api/[controller]")]
[Produces("application/json")]
public sealed class StatusController : ControllerBase
{
    private readonly ITamperProofLogStorage _storage;
    private readonly ISigmaRuleEngine _sigmaEngine;
    private readonly TumLogOptions _tumLogOptions;
    private readonly SiemServerOptions _options;

    public StatusController(
        ITamperProofLogStorage storage,
        ISigmaRuleEngine sigmaEngine,
        TumLogOptions tumLogOptions,
        IOptions<SiemServerOptions> options)
    {
        _storage = storage ?? throw new ArgumentNullException(nameof(storage));
        _sigmaEngine = sigmaEngine ?? throw new ArgumentNullException(nameof(sigmaEngine));
        _tumLogOptions = tumLogOptions ?? throw new ArgumentNullException(nameof(tumLogOptions));
        _options = options?.Value ?? new SiemServerOptions();
    }

    /// <summary>
    /// Checks the operational status, Merkle integrity seal, and active rule engine metrics.
    /// </summary>
    [HttpGet]
    [ProducesResponseType(typeof(SystemStatusResponse), StatusCodes.Status200OK)]
    public async Task<IActionResult> GetStatus(CancellationToken cancellationToken)
    {
        bool intact = await _storage.VerifyChainIntegrityAsync();
        var recent = await _storage.GetRecentEntriesAsync(1);
        string lastHash = recent.Count > 0 ? recent[0].TamperProofHash : "GENESIS_LEGAL_SEAL";
        string merkleRoot = recent.Count > 0 ? recent[0].MerkleRoot : "GENESIS_MERKLE_ROOT";

        var response = new SystemStatusResponse
        {
            Engine = "TUM-OpenSIEM Sovereign Edition",
            Version = "2.0.0-PROD",
            Status = "Operational",
            ChainIntact = intact,
            LastTamperProofHash = lastHash,
            GlobalMerkleRoot = merkleRoot,
            ActiveSigmaRules = _sigmaEngine.ActiveRuleCount,
            NtpSynchronizedWith = _tumLogOptions.NtpServerHost ?? _options.NtpServerHost,
            WormRetentionDays = _tumLogOptions.WormRetentionDays,
            TimestampUtc = DateTimeOffset.UtcNow
        };

        return Ok(response);
    }
}
