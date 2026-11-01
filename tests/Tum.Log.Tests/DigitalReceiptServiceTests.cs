// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using System.Threading.Tasks;
using Tum.Siem.Server.Models;
using Tum.Siem.Server.Services;
using Xunit;

namespace Tum.Trust.Security.Tests;

public class DigitalReceiptServiceTests
{
    [Fact]
    public async Task RecordReceiptAsync_ChainsMerkleLeafAndPersistsEntry()
    {
        var service = new DigitalReceiptService();
        var request = new ReceiptSubmissionRequest
        {
            ReceiptId = "REC-BKK-2026-001",
            TransactionRef = "TXN-ETAX-987654",
            IssuerDid = "did:tum:tax:revenue-th",
            PayloadHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            FiscalAmountThb = 15990.50m,
            SignatureHex = "3045022100abc123456789def0123456789abcde",
            PqcAlgorithm = "NIST_FIPS_204_ML_DSA_87"
        };

        var entry = await service.RecordReceiptAsync(request);

        Assert.NotNull(entry);
        Assert.Equal("REC-BKK-2026-001", entry.ReceiptId);
        Assert.Equal("TXN-ETAX-987654", entry.TransactionRef);
        Assert.False(string.IsNullOrWhiteSpace(entry.LeafHash));
        Assert.Equal("0000000000000000000000000000000000000000000000000000000000000000", entry.PreviousHash);
        Assert.Equal(1, service.GetLedgerCount());
        Assert.Equal(entry.LeafHash, service.GetCurrentMerkleRoot());
    }

    [Fact]
    public async Task VerifyReceiptAsync_SucceedsForAuthenticPayload()
    {
        var service = new DigitalReceiptService();
        var submission = new ReceiptSubmissionRequest
        {
            ReceiptId = "REC-BKK-2026-002",
            TransactionRef = "TXN-ETAX-987655",
            IssuerDid = "did:tum:tax:revenue-th",
            PayloadHash = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
            FiscalAmountThb = 2500.00m,
            SignatureHex = "abcdef1234567890",
            PqcAlgorithm = "NIST_FIPS_204_ML_DSA_87"
        };

        await service.RecordReceiptAsync(submission);

        var verifyRequest = new ReceiptVerificationRequest
        {
            ReceiptId = "REC-BKK-2026-002",
            ExpectedPayloadHash = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
        };

        var result = await service.VerifyReceiptAsync(verifyRequest);

        Assert.NotNull(result);
        Assert.True(result.IsValid);
        Assert.True(result.IsMerkleChained);
        Assert.True(result.IsTamperProof);
        Assert.NotNull(result.AuditProofHex);
        Assert.Contains("authentic", result.StatusMessage, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task VerifyReceiptAsync_DetectsTamperedPayload()
    {
        var service = new DigitalReceiptService();
        var submission = new ReceiptSubmissionRequest
        {
            ReceiptId = "REC-BKK-2026-003",
            TransactionRef = "TXN-ETAX-987656",
            IssuerDid = "did:tum:tax:revenue-th",
            PayloadHash = "original-genuine-payload-hash-value-001",
            FiscalAmountThb = 999.00m,
            SignatureHex = "sig-hex-valid",
            PqcAlgorithm = "NIST_FIPS_204_ML_DSA_87"
        };

        await service.RecordReceiptAsync(submission);

        var verifyRequest = new ReceiptVerificationRequest
        {
            ReceiptId = "REC-BKK-2026-003",
            ExpectedPayloadHash = "forged-tampered-payload-hash-value-002"
        };

        var result = await service.VerifyReceiptAsync(verifyRequest);

        Assert.NotNull(result);
        Assert.False(result.IsValid);
        Assert.False(result.IsTamperProof);
        Assert.Contains("tampering", result.StatusMessage, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task VerifyReceiptAsync_ReturnsFalseForUnknownReceipt()
    {
        var service = new DigitalReceiptService();
        var verifyRequest = new ReceiptVerificationRequest
        {
            ReceiptId = "NON-EXISTENT-RECEIPT",
            ExpectedPayloadHash = "some-hash"
        };

        var result = await service.VerifyReceiptAsync(verifyRequest);

        Assert.NotNull(result);
        Assert.False(result.IsValid);
        Assert.False(result.IsMerkleChained);
        Assert.Contains("not found", result.StatusMessage, StringComparison.OrdinalIgnoreCase);
    }
}
