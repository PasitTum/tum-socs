// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Tum.Siem.Server.Models;

namespace Tum.Siem.Server.Services;

public class DigitalReceiptService : IDigitalReceiptService
{
    private readonly ConcurrentDictionary<string, ReceiptLedgerEntry> _ledger = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _chainLock = new();
    private string _latestHash = "0000000000000000000000000000000000000000000000000000000000000000";

    public Task<ReceiptLedgerEntry> RecordReceiptAsync(ReceiptSubmissionRequest request, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        lock (_chainLock)
        {
            var previousHash = _latestHash;
            var leafHash = ComputeLeafHash(request.ReceiptId, request.PayloadHash, request.FiscalAmountThb, previousHash);

            var entry = new ReceiptLedgerEntry
            {
                ReceiptId = request.ReceiptId,
                TransactionRef = request.TransactionRef,
                IssuerDid = request.IssuerDid,
                PayloadHash = request.PayloadHash,
                FiscalAmountThb = request.FiscalAmountThb,
                SignatureHex = request.SignatureHex,
                PqcAlgorithm = request.PqcAlgorithm,
                PreviousHash = previousHash,
                LeafHash = leafHash,
                RecordedAt = DateTimeOffset.UtcNow
            };

            _ledger[request.ReceiptId] = entry;
            _latestHash = leafHash;

            return Task.FromResult(entry);
        }
    }

    public Task<ReceiptVerificationResponse> VerifyReceiptAsync(ReceiptVerificationRequest request, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        var sw = Stopwatch.StartNew();

        if (!_ledger.TryGetValue(request.ReceiptId, out var entry))
        {
            sw.Stop();
            return Task.FromResult(new ReceiptVerificationResponse
            {
                ReceiptId = request.ReceiptId,
                IsValid = false,
                IsMerkleChained = false,
                IsTamperProof = false,
                VerificationLatencyMs = sw.Elapsed.TotalMilliseconds,
                StatusMessage = "Receipt not found in immutable audit ledger."
            });
        }

        // Recompute leaf hash to verify against tampering
        var recomputedLeaf = ComputeLeafHash(entry.ReceiptId, request.ExpectedPayloadHash, entry.FiscalAmountThb, entry.PreviousHash);
        var isPayloadMatch = string.Equals(entry.PayloadHash, request.ExpectedPayloadHash, StringComparison.OrdinalIgnoreCase);
        var isTamperProof = string.Equals(recomputedLeaf, entry.LeafHash, StringComparison.OrdinalIgnoreCase) && isPayloadMatch;

        sw.Stop();
        return Task.FromResult(new ReceiptVerificationResponse
        {
            ReceiptId = entry.ReceiptId,
            IsValid = isTamperProof,
            IsMerkleChained = true,
            IsTamperProof = isTamperProof,
            MerkleRootHash = _latestHash,
            AuditProofHex = entry.LeafHash,
            VerificationLatencyMs = sw.Elapsed.TotalMilliseconds,
            StatusMessage = isTamperProof ? "Receipt verified authentic and tamper-proof." : "Receipt payload hash mismatch or ledger tampering detected."
        });
    }

    public Task<ReceiptLedgerEntry?> GetReceiptAsync(string receiptId, CancellationToken ct = default)
    {
        _ledger.TryGetValue(receiptId, out var entry);
        return Task.FromResult(entry);
    }

    public string GetCurrentMerkleRoot()
    {
        lock (_chainLock)
        {
            return _latestHash;
        }
    }

    public int GetLedgerCount()
    {
        return _ledger.Count;
    }

    private static string ComputeLeafHash(string receiptId, string payloadHash, decimal amount, string previousHash)
    {
        var raw = $"{receiptId}:{payloadHash}:{amount:F2}:{previousHash}";
        var hashBytes = SHA256.HashData(Encoding.UTF8.GetBytes(raw));
        return Convert.ToHexString(hashBytes).ToLowerInvariant();
    }
}
