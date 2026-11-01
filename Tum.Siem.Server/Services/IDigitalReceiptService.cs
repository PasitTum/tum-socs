// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Threading;
using System.Threading.Tasks;
using Tum.Siem.Server.Models;

namespace Tum.Siem.Server.Services;

public interface IDigitalReceiptService
{
    Task<ReceiptLedgerEntry> RecordReceiptAsync(ReceiptSubmissionRequest request, CancellationToken ct = default);
    Task<ReceiptVerificationResponse> VerifyReceiptAsync(ReceiptVerificationRequest request, CancellationToken ct = default);
    Task<ReceiptLedgerEntry?> GetReceiptAsync(string receiptId, CancellationToken ct = default);
    string GetCurrentMerkleRoot();
    int GetLedgerCount();
}
