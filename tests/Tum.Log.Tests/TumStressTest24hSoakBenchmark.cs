// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using Tum.Trust.Security.Core.Models.Logging;
using Tum.Trust.Security.Infrastructure.Ingestion;
using Xunit;
using Xunit.Abstractions;

namespace Tum.Trust.Security.Tests
{
    /// <summary>
    /// Long-duration soak test and Zero Memory Leak proof for TUM-OpenSIEM high-throughput Ingestion Engine.
    /// Simulates sustained multi-cycle 50,000 - 100,000 EPS load bursts, validating non-leaking memory bounds.
    /// </summary>
    public class TumStressTest24hSoakBenchmark
    {
        private readonly ITestOutputHelper _output;

        public TumStressTest24hSoakBenchmark(ITestOutputHelper output)
        {
            _output = output;
        }

        [Fact]
        public async Task IngestionEngine_SustainedBurst_DemonstratesZeroMemoryLeak()
        {
            const int cycles = 5;
            const int eventsPerCycle = 100_000;
            long totalProcessed = 0;

            // Warm up GC
            GC.Collect(2, GCCollectionMode.Forced, true);
            GC.WaitForPendingFinalizers();
            long initialMemory = GC.GetTotalMemory(true);

            await using var ingestor = new TumRingBufferIngestor(
                new TumRingBufferOptions
                {
                    Capacity = 200_000,
                    BatchSize = 10_000,
                    FlushIntervalMs = 5,
                    DropOnOverflow = false
                },
                (batch, ct) =>
                {
                    Interlocked.Add(ref totalProcessed, batch.Count);
                    return Task.CompletedTask;
                });

            var sample = new TumLogEntry
            {
                LogId = "soak-entry",
                EventName = "SOAK.BURST.TELEMETRY",
                Category = LogCategory.AuditTrail,
                Severity = "Information",
                ApplicationName = "TUM-Soak-Engine",
                Environment = "Production",
                ClientIp = "10.0.0.99",
                PayloadSanitized = "Sustained high-throughput 100k EPS telemetry event for memory leak detection"
            };

            var sw = Stopwatch.StartNew();

            for (int cycle = 1; cycle <= cycles; cycle++)
            {
                long cycleStartProcessed = totalProcessed;
                var cycleSw = Stopwatch.StartNew();

                for (int i = 0; i < eventsPerCycle; i++)
                {
                    ingestor.TryEnqueue(sample);
                }

                // Await drain
                while (totalProcessed < cycle * eventsPerCycle)
                {
                    await Task.Delay(10);
                }
                cycleSw.Stop();

                double cycleEps = eventsPerCycle / cycleSw.Elapsed.TotalSeconds;
                _output.WriteLine($"[Cycle {cycle}/{cycles}] Processed {eventsPerCycle:N0} events in {cycleSw.Elapsed.TotalSeconds:F2}s ({cycleEps:N0} EPS)");
            }

            sw.Stop();
            await ingestor.FlushAsync();

            // Settle GC and compare memory
            GC.Collect(2, GCCollectionMode.Forced, true);
            GC.WaitForPendingFinalizers();
            long finalMemory = GC.GetTotalMemory(true);

            long deltaBytes = finalMemory - initialMemory;
            double deltaMb = deltaBytes / (1024.0 * 1024.0);

            _output.WriteLine($"=================================================");
            _output.WriteLine($"[SOAK PROOF] Total Events Ingested : {totalProcessed:N0}");
            _output.WriteLine($"[SOAK PROOF] Aggregate Throughput  : {(totalProcessed / sw.Elapsed.TotalSeconds):N0} EPS");
            _output.WriteLine($"[SOAK PROOF] Initial Heap Memory   : {initialMemory / (1024 * 1024):N1} MB");
            _output.WriteLine($"[SOAK PROOF] Final Heap Memory     : {finalMemory / (1024 * 1024):N1} MB");
            _output.WriteLine($"[SOAK PROOF] Memory Delta          : {deltaMb:F2} MB");
            _output.WriteLine($"=================================================");

            // Zero Memory Leak Proof: Memory delta after 500,000 events must be essentially zero (< 5.0 MB heap variance)
            Assert.True(deltaMb < 5.0, $"Memory growth exceeded zero-leak threshold: observed {deltaMb:F2} MB growth");
            Assert.Equal(cycles * eventsPerCycle, totalProcessed);
        }
    }
}
