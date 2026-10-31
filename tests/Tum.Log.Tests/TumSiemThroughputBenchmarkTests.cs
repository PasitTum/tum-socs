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
    public class TumSiemThroughputBenchmarkTests
    {
        private readonly ITestOutputHelper _output;

        public TumSiemThroughputBenchmarkTests(ITestOutputHelper output)
        {
            _output = output;
        }

        [Fact]
        public async Task IngestionEngine_Exceeds_50000_EPS_Benchmark()
        {
            const int targetEvents = 100_000;
            var tcs = new TaskCompletionSource<bool>();
            long processedCount = 0;

            await using var ingestor = new TumRingBufferIngestor(
                new TumRingBufferOptions
                {
                    Capacity = 200_000,
                    BatchSize = 10_000,
                    FlushIntervalMs = 10,
                    DropOnOverflow = false
                },
                (batch, ct) =>
                {
                    long current = Interlocked.Add(ref processedCount, batch.Count);
                    if (current >= targetEvents)
                    {
                        tcs.TrySetResult(true);
                    }
                    return Task.CompletedTask;
                });

            // Pre-create sample log entry to isolate engine channel throughput
            var sample = new TumLogEntry
            {
                LogId = "bench-entry",
                EventName = "TELEMETRY.METRIC",
                Category = LogCategory.AuditTrail,
                Severity = "Information",
                ApplicationName = "TUM-Benchmark-Engine",
                Environment = "Benchmark",
                ClientIp = "127.0.0.1",
                PayloadSanitized = "Telemetry ping payload for high throughput benchmark verification"
            };

            var sw = Stopwatch.StartNew();

            for (int i = 0; i < targetEvents; i++)
            {
                ingestor.TryEnqueue(sample);
            }

            var timeoutTask = Task.Delay(5000);
            var finished = await Task.WhenAny(tcs.Task, timeoutTask);
            sw.Stop();

            Assert.Same(tcs.Task, finished);

            double seconds = sw.Elapsed.TotalSeconds;
            double eps = targetEvents / seconds;
            int coreCount = Environment.ProcessorCount;
            double epsPerCore = eps / coreCount;

            _output.WriteLine($"[TUM-OpenSIEM Benchmark] Total Events: {targetEvents:N0} in {seconds:F3}s");
            _output.WriteLine($"[TUM-OpenSIEM Benchmark] Total EPS: {eps:N0} events/sec");
            _output.WriteLine($"[TUM-OpenSIEM Benchmark] Processor Cores: {coreCount}");
            _output.WriteLine($"[TUM-OpenSIEM Benchmark] EPS per Core: {epsPerCore:N0} events/sec/core");

            // RFC Sprint 1 Criterion: High throughput capable of > 50,000 EPS
            Assert.True(eps >= 50_000, $"Expected at least 50,000 EPS, but observed {eps:N0} EPS");
        }
    }
}
