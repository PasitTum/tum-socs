using System.Security.Cryptography;
using System.Text;
using Tum.Log.Core.Models.Ebpf;
using Tum.Log.Infrastructure.Ebpf;
using Tum.Trust.Security.Core.Models.Logging;
using Tum.Trust.Security.Infrastructure.Ingestion;
using Xunit;

namespace Tum.Log.Tests;

public class EbpfFileHookMonitorTests
{
    [Fact]
    public void VerifyBinaryIntegrity_MatchingBaseline_ReturnsTrue()
    {
        var monitor = new EbpfFileHookMonitor();
        byte[] content = Encoding.UTF8.GetBytes("AUTHENTIC_TEST_BINARY_v1.0.0");
        string expectedHash = Convert.ToHexString(SHA256.HashData(content)).ToLowerInvariant();

        monitor.RegisterBinaryBaseline("/opt/tum/engine.bin", expectedHash);

        bool isValid = monitor.VerifyBinaryIntegrity("/opt/tum/engine.bin", content);
        Assert.True(isValid);
    }

    [Fact]
    public void VerifyBinaryIntegrity_MismatchedBaseline_ReturnsFalse()
    {
        var monitor = new EbpfFileHookMonitor();
        byte[] originalContent = Encoding.UTF8.GetBytes("AUTHENTIC_TEST_BINARY_v1.0.0");
        string expectedHash = Convert.ToHexString(SHA256.HashData(originalContent)).ToLowerInvariant();

        monitor.RegisterBinaryBaseline("/opt/tum/engine.bin", expectedHash);

        byte[] modifiedContent = Encoding.UTF8.GetBytes("MODIFIED_BACKDOORED_BINARY_v1.0.0");
        bool isValid = monitor.VerifyBinaryIntegrity("/opt/tum/engine.bin", modifiedContent);
        Assert.False(isValid);
    }

    [Fact]
    public void IngestFileSyscall_UnauthorizedBinaryModification_DetectsTamperingWithMitreT1565()
    {
        var monitor = new EbpfFileHookMonitor();
        monitor.RegisterBinaryBaseline("/usr/bin/sudo", "0000000000000000000000000000000000000000000000000000000000000001");

        var rawTrace = new EbpfFileTraceRaw
        {
            Pid = 4120,
            Uid = 0,
            ProcessName = "malware_installer",
            FilePath = "/usr/bin/sudo",
            Syscall = EbpfFileSyscall.Write,
            BufferContent = Encoding.UTF8.GetBytes("EVIL_SUDO_MODIFICATION"),
            Timestamp = DateTime.UtcNow
        };

        var ev = monitor.IngestFileSyscall(rawTrace);

        Assert.NotNull(ev);
        Assert.True(ev!.IsTampering);
        Assert.Equal("Critical", ev.Severity);
        Assert.Equal("T1565.001", ev.MitreTechniqueId);
        Assert.Contains("Unauthorized modification of critical binary", ev.ThreatDetails);

        var stats = monitor.GetStatistics();
        Assert.Equal(1, stats.TotalFileEventsCaptured);
        Assert.Equal(1, stats.BinaryModificationsDetected);
        Assert.Equal(1, stats.TamperingAlertsGenerated);

        var alerts = monitor.GetRecentTamperingAlerts();
        Assert.Single(alerts);
        Assert.Equal("/usr/bin/sudo", alerts[0].FilePath);
    }

    [Fact]
    public void IngestFileSyscall_AntiForensicLogDeletion_DetectsCriticalLogWipeWithMitreT1070()
    {
        var monitor = new EbpfFileHookMonitor();

        var rawTrace = new EbpfFileTraceRaw
        {
            Pid = 8831,
            Uid = 0,
            ProcessName = "rm",
            FilePath = "/var/log/tum-siem/tum_logs_audit_20261101.jsonl",
            Syscall = EbpfFileSyscall.UnlinkAt,
            Timestamp = DateTime.UtcNow
        };

        var ev = monitor.IngestFileSyscall(rawTrace);

        Assert.NotNull(ev);
        Assert.True(ev!.IsTampering);
        Assert.Equal("Critical", ev.Severity);
        Assert.Equal("T1070.004", ev.MitreTechniqueId);
        Assert.Contains("Anti-Forensics: Attempted deletion (unlink) of tamper-proof WORM ledger file", ev.ThreatDetails);

        var stats = monitor.GetStatistics();
        Assert.Equal(1, stats.DeletionsIntercepted);
        Assert.Equal(1, stats.TamperingAlertsGenerated);
    }

    [Fact]
    public void IngestFileSyscall_PermissionManipulation_DetectsSetUidEscalationWithMitreT1548()
    {
        var monitor = new EbpfFileHookMonitor();

        var rawTrace = new EbpfFileTraceRaw
        {
            Pid = 7120,
            Uid = 1000,
            ProcessName = "chmod",
            FilePath = "/tmp/backdoor",
            Syscall = EbpfFileSyscall.Chmod,
            ModeOrPermissions = "4755", // SetUID bit enabled
            Timestamp = DateTime.UtcNow
        };

        var ev = monitor.IngestFileSyscall(rawTrace);

        Assert.NotNull(ev);
        Assert.True(ev!.IsTampering);
        Assert.Equal("High", ev.Severity);
        Assert.Equal("T1548.001", ev.MitreTechniqueId);
        Assert.Contains("Privilege Escalation: SetUID", ev.ThreatDetails);

        var stats = monitor.GetStatistics();
        Assert.Equal(1, stats.PermissionEscalations);
    }

    [Fact]
    public void IngestFileSyscall_RansomwareRenaming_DetectsExtortionPatternWithMitreT1486()
    {
        var monitor = new EbpfFileHookMonitor();

        var rawTrace = new EbpfFileTraceRaw
        {
            Pid = 9912,
            Uid = 0,
            ProcessName = "lockbit.exe",
            FilePath = "/data/finance/q4_forecast.xlsx",
            NewFilePath = "/data/finance/q4_forecast.xlsx.locked",
            Syscall = EbpfFileSyscall.RenameAt,
            Timestamp = DateTime.UtcNow
        };

        var ev = monitor.IngestFileSyscall(rawTrace);

        Assert.NotNull(ev);
        Assert.True(ev!.IsTampering);
        Assert.Equal("Critical", ev.Severity);
        Assert.Equal("T1486", ev.MitreTechniqueId);
        Assert.Contains("Ransomware Activity: Target file", ev.ThreatDetails);

        var stats = monitor.GetStatistics();
        Assert.Equal(1, stats.RansomwarePatternsDetected);
    }

    [Fact]
    public async Task IngestFileSyscall_WithRingBuffer_EnqueuesSecurityThreatEntry()
    {
        var received = new List<TumLogEntry>();
        var tcs = new TaskCompletionSource<bool>();

        await using var ringBuffer = new TumRingBufferIngestor(
            new TumRingBufferOptions
            {
                Capacity = 100,
                BatchSize = 1,
                FlushIntervalMs = 10
            },
            (batch, ct) =>
            {
                lock (received)
                {
                    received.AddRange(batch);
                    tcs.TrySetResult(true);
                }
                return Task.CompletedTask;
            });

        var options = new EbpfFileHookOptions { AutoStreamToRingBuffer = true };
        var monitor = new EbpfFileHookMonitor(options, ringBuffer);
        monitor.RegisterBinaryBaseline("/bin/bash", "0000000000000000000000000000000000000000000000000000000000000002");

        var rawTrace = new EbpfFileTraceRaw
        {
            Pid = 5544,
            Uid = 0,
            ProcessName = "rootkit_injector",
            FilePath = "/bin/bash",
            Syscall = EbpfFileSyscall.Write,
            BufferContent = Encoding.UTF8.GetBytes("MODIFIED_SHELL_PAYLOAD"),
            Timestamp = DateTime.UtcNow
        };

        monitor.IngestFileSyscall(rawTrace);

        var completedTask = await Task.WhenAny(tcs.Task, Task.Delay(2000));
        Assert.True(completedTask == tcs.Task, "Timed out waiting for RingBuffer batch dispatch.");

        lock (received)
        {
            Assert.NotEmpty(received);
            var entry = received.First();
            Assert.Equal(LogCategory.SecurityThreat, entry.Category);
            Assert.Equal("File.eBPF.T1565.001", entry.EventName);
            Assert.Equal("Critical", entry.Severity);
            Assert.Contains("/bin/bash", entry.PayloadSanitized);
            Assert.Equal("TUMSocs-eBPF-FIM", entry.ApplicationName);
        }
    }

    [Fact]
    public void IngestFileSyscall_HighThroughputConcurrentIngestion_ThreadSafeExecution()
    {
        var monitor = new EbpfFileHookMonitor();
        int taskCount = 10;
        int eventsPerTask = 100;

        Parallel.For(0, taskCount, taskId =>
        {
            for (int i = 0; i < eventsPerTask; i++)
            {
                var rawTrace = new EbpfFileTraceRaw
                {
                    Pid = 1000 + taskId,
                    Uid = 1000,
                    ProcessName = $"worker_proc_{taskId}",
                    FilePath = $"/tmp/data_worker_{taskId}_{i}.dat",
                    Syscall = EbpfFileSyscall.Write,
                    BufferContent = Encoding.UTF8.GetBytes($"Payload_{taskId}_{i}"),
                    Timestamp = DateTime.UtcNow
                };

                monitor.IngestFileSyscall(rawTrace);
            }
        });

        var stats = monitor.GetStatistics();
        Assert.Equal(taskCount * eventsPerTask, stats.TotalFileEventsCaptured);
    }
}
