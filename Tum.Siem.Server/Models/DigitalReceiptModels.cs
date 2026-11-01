// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;

namespace Tum.Siem.Server.Models;

public record ReceiptSubmissionRequest
{
    public required string ReceiptId { get; init; }
    public required string TransactionRef { get; init; }
    public required string IssuerDid { get; init; }
    public required string PayloadHash { get; init; }
    public decimal FiscalAmountThb { get; init; }
    public required string SignatureHex { get; init; }
    public string PqcAlgorithm { get; init; } = "NIST_FIPS_204_ML_DSA_87";
    public DateTimeOffset Timestamp { get; init; } = DateTimeOffset.UtcNow;
}

public record ReceiptVerificationRequest
{
    public required string ReceiptId { get; init; }
    public required string ExpectedPayloadHash { get; init; }
}

public record ReceiptVerificationResponse
{
    public required string ReceiptId { get; init; }
    public bool IsValid { get; init; }
    public bool IsMerkleChained { get; init; }
    public bool IsTamperProof { get; init; }
    public string? MerkleRootHash { get; init; }
    public string? AuditProofHex { get; init; }
    public double VerificationLatencyMs { get; init; }
    public string? StatusMessage { get; init; }
}

public record ReceiptLedgerEntry
{
    public required string ReceiptId { get; init; }
    public required string TransactionRef { get; init; }
    public required string IssuerDid { get; init; }
    public required string PayloadHash { get; init; }
    public decimal FiscalAmountThb { get; init; }
    public required string SignatureHex { get; init; }
    public required string PqcAlgorithm { get; init; }
    public required string PreviousHash { get; init; }
    public required string LeafHash { get; init; }
    public DateTimeOffset RecordedAt { get; init; }
}
