// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Tum.Trust.Security.Core.Models.Logging;
using Tum.Trust.Security.Infrastructure.Ingestion;
using Xunit;

namespace Tum.Trust.Security.Tests
{
    public class TumRingBufferIngestorTests
    {
        [Fact]
        public async Task RingBuffer_ProcessesBatchesAsynchronously()
        {
            var processedBatches = new List<IReadOnlyList<TumLogEntry>>();
            var tcs = new TaskCompletionSource<bool>();
            int expectedCount = 50;

            await using var ingestor = new TumRingBufferIngestor(
                new TumRingBufferOptions
                {
                    Capacity = 1000,
                    BatchSize = 10,
                    FlushIntervalMs = 20
                },
                (batch, ct) =>
                {
                    lock (processedBatches)
                    {
                        var copy = new List<TumLogEntry>(batch);
                        processedBatches.Add(copy);
                        int total = 0;
                        foreach (var b in processedBatches) total += b.Count;
                        if (total >= expectedCount)
                        {
                            tcs.TrySetResult(true);
                        }
                    }
                    return Task.CompletedTask;
                });

            for (int i = 0; i < expectedCount; i++)
            {
                bool enqueued = ingestor.TryEnqueue(new TumLogEntry
                {
                    LogId = $"log-{i}",
                    EventName = "TEST.EVENT"
                });
                Assert.True(enqueued);
            }

            var timeoutTask = Task.Delay(3000);
            var completed = await Task.WhenAny(tcs.Task, timeoutTask);
            Assert.Same(tcs.Task, completed);

            await ingestor.FlushAsync();
            var stats = ingestor.GetStats();

            Assert.Equal(expectedCount, stats.TotalEnqueued);
            Assert.True(stats.TotalProcessed >= expectedCount);
            Assert.Equal(0, stats.TotalDropped);
        }

        [Fact]
        public void RingBuffer_DropOnOverflow_DropsWhenCapacityExceeded()
        {
            int smallCapacity = 5;
            using var ingestor = new TumRingBufferIngestor(
                new TumRingBufferOptions
                {
                    Capacity = smallCapacity,
                    BatchSize = 100,
                    DropOnOverflow = true
                },
                async (batch, ct) =>
                {
                    // Delay to allow queue to fill up
                    await Task.Delay(1000, ct);
                });

            int accepted = 0;
            int dropped = 0;

            for (int i = 0; i < 50; i++)
            {
                if (ingestor.TryEnqueue(new TumLogEntry { LogId = $"drop-test-{i}" }))
                {
                    accepted++;
                }
                else
                {
                    dropped++;
                }
            }

            var stats = ingestor.GetStats();
            Assert.True(dropped > 0, "Expected some items to be dropped when capacity is exceeded");
            Assert.Equal(dropped, stats.TotalDropped);
        }
    }
}
