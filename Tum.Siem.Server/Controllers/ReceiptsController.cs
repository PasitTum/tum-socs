// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Tum.Siem.Server.Models;
using Tum.Siem.Server.Services;

namespace Tum.Siem.Server.Controllers;

[ApiController]
[Route("api/v1/receipts")]
public class ReceiptsController : ControllerBase
{
    private readonly IDigitalReceiptService _receiptService;

    public ReceiptsController(IDigitalReceiptService receiptService)
    {
        _receiptService = receiptService;
    }

    [HttpPost("record")]
    public async Task<IActionResult> RecordReceipt([FromBody] ReceiptSubmissionRequest request, CancellationToken ct)
    {
        if (request == null || string.IsNullOrWhiteSpace(request.ReceiptId))
        {
            return BadRequest(new { error = "ReceiptId is required." });
        }

        var entry = await _receiptService.RecordReceiptAsync(request, ct);
        return CreatedAtAction(nameof(GetReceipt), new { id = entry.ReceiptId }, entry);
    }

    [HttpPost("verify")]
    public async Task<IActionResult> VerifyReceipt([FromBody] ReceiptVerificationRequest request, CancellationToken ct)
    {
        if (request == null || string.IsNullOrWhiteSpace(request.ReceiptId))
        {
            return BadRequest(new { error = "ReceiptId is required." });
        }

        var response = await _receiptService.VerifyReceiptAsync(request, ct);
        return Ok(response);
    }

    [HttpGet("{id}")]
    public async Task<IActionResult> GetReceipt(string id, CancellationToken ct)
    {
        var entry = await _receiptService.GetReceiptAsync(id, ct);
        if (entry == null)
        {
            return NotFound(new { error = $"Receipt {id} not found." });
        }

        return Ok(entry);
    }

    [HttpGet("root")]
    public IActionResult GetLedgerRoot()
    {
        var root = _receiptService.GetCurrentMerkleRoot();
        var count = _receiptService.GetLedgerCount();
        return Ok(new { merkleRoot = root, totalReceipts = count });
    }
}
